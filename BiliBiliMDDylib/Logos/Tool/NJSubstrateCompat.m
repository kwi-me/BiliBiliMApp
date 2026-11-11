//
//  NJSubstrateCompat.m
//  BiliBiliMDDylib
//
//  自包含的 Substrate 兼容层。
//
//  背景：工程原先链接 /opt/MonkeyDev/Frameworks/libsubstrate.dylib，链接结果是一条
//  LC_LOAD_WEAK_DYLIB -> /Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate。
//  该路径只在越狱环境下存在；TrollStore / 非越狱环境里 dyld 会跳过这条弱依赖，
//  于是 MSHookMessageEx / MSHookFunction 在运行时被解析成 NULL，
//  Logos 生成的 %ctor 拿不到 hook 入口，整个插件的所有 hook 静默失效。
//
//  本文件提供两个符号的自实现：
//    1. 如果进程里已经加载了真实的 Substrate（TrollFools 会注入 CydiaSubstrate.framework），
//       优先转发给它，行为与越狱环境完全一致；
//    2. 否则使用内置实现，不依赖任何外部库。
//
//  内置实现的覆盖范围：
//    - MSHookMessageEx：完整的 ObjC 方法替换，含"继承方法在本类加覆盖"的语义
//    - MSHookFunction：arm64 保守版 inline hook，仅在前 4 条指令可安全重定位时生效，
//      否则不做改动并把 orig 指回原函数，保证不崩溃
//

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <string.h>
#import <stdlib.h>
#import <mach/mach.h>
#import <mach/vm_map.h>
#import <libkern/OSCacheControl.h>

#define NJ_HIDDEN __attribute__((visibility("hidden")))

#pragma mark - 诊断状态（供 NJProbe 读取）

/// 0 = 尚未调用过，1 = 使用内置实现，2 = 转发给进程内真实 Substrate
static int NJ_gMode = 0;
static int NJ_gHookMessageCount = 0;
static int NJ_gHookFunctionCount = 0;

int NJSubstrateMode(void) { return NJ_gMode; }
int NJHookMessageCount(void) { return NJ_gHookMessageCount; }
int NJHookFunctionCount(void) { return NJ_gHookFunctionCount; }

#pragma mark - 内置实现：MSHookMessageEx

static void NJHookMessageExImpl(Class cls, SEL sel, IMP replacement, IMP *original) {
    if (!cls || !sel || !replacement) {
        if (original) *original = NULL;
        return;
    }

    Method method = class_getInstanceMethod(cls, sel);
    if (!method) {
        // 目标方法不存在（版本不符）：按 Substrate 的做法补一个
        NSLog(@"[NJ] MSHookMessageEx: %s 没有实现 %s，直接新增",
              class_getName(cls), sel_getName(sel));
        class_addMethod(cls, sel, replacement, NULL);
        if (original) *original = NULL;
        return;
    }

    // class_copyMethodList 只返回本类自身实现的方法；
    // 若查不到，说明该方法继承自父类，此时必须在本类新增覆盖，
    // 否则 method_setImplementation 会改到父类上，波及所有子类。
    BOOL ownedBySelf = NO;
    unsigned int count = 0;
    Method *methods = class_copyMethodList(cls, &count);
    if (methods) {
        for (unsigned int i = 0; i < count; i++) {
            if (sel_isEqual(method_getName(methods[i]), sel)) {
                ownedBySelf = YES;
                break;
            }
        }
        free(methods);
    }

    IMP oldIMP = method_getImplementation(method);
    if (original) *original = oldIMP;

    if (ownedBySelf) {
        method_setImplementation(method, replacement);
    } else {
        class_addMethod(cls, sel, replacement, method_getTypeEncoding(method));
    }
}

#pragma mark - 内置实现：MSHookFunction（arm64）

static BOOL NJReadMemory(void *address, void *buffer, size_t length) {
    vm_size_t outSize = 0;
    kern_return_t kr = vm_read_overwrite(mach_task_self(),
                                         (vm_address_t)address,
                                         (vm_size_t)length,
                                         (vm_address_t)buffer,
                                         &outSize);
    return kr == KERN_SUCCESS && outSize == length;
}

/// 判断一条 arm64 指令是否依赖 PC 相对寻址。
/// 这类指令一旦被搬运到 trampoline，偏移基准就变了，必须重定位；
/// 本实现在遇到它们时直接放弃 hook，宁可失效也不写坏代码。
static BOOL NJInstructionNeedsRelocation(uint32_t insn) {
    if ((insn & 0x1F000000u) == 0x10000000u) return YES; // ADR / ADRP
    if ((insn & 0x7C000000u) == 0x14000000u) return YES; // B / BL
    if ((insn & 0xFF000010u) == 0x54000000u) return YES; // B.cond / BC.cond
    if ((insn & 0x7E000000u) == 0x34000000u) return YES; // CBZ / CBNZ
    if ((insn & 0x7E000000u) == 0x36000000u) return YES; // TBZ / TBNZ
    if ((insn & 0x3B000000u) == 0x18000000u) return YES; // LDR (literal)
    if ((insn & 0xFF000000u) == 0xD8000000u) return YES; // PRFM (literal)
    return NO;
}

/// 生成 16 字节的绝对跳转：
///   LDR X16, #8      ; 0x58000050
///   BR  X16          ; 0xD61F0200
///   .quad <target>
static void NJWriteAbsoluteJump(uint32_t *dst, void *target) {
    dst[0] = 0x58000050u;
    dst[1] = 0xD61F0200u;
    uint64_t addr = (uint64_t)target;
    memcpy(&dst[2], &addr, sizeof(addr));
}

static void *NJHookFunctionImpl(void *target, void *replacement) {
    if (!target || !replacement) return NULL;

    uint32_t prologue[4] = {0};
    if (!NJReadMemory(target, prologue, sizeof(prologue))) {
        NSLog(@"[NJ] MSHookFunction: 无法读取目标地址 %p", target);
        return NULL;
    }

    for (int i = 0; i < 4; i++) {
        if (NJInstructionNeedsRelocation(prologue[i])) {
            NSLog(@"[NJ] MSHookFunction: %p 函数序言含 PC 相对指令，跳过 hook", target);
            return NULL;
        }
    }

    // 1. 分配 trampoline 并写入 4 条原始指令 + 跳回 target+16
    vm_address_t trampoline = 0;
    kern_return_t kr = vm_allocate(mach_task_self(), &trampoline, 0x4000, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        NSLog(@"[NJ] MSHookFunction: trampoline 分配失败 (%d)", kr);
        return NULL;
    }
    vm_protect(mach_task_self(), trampoline, 0x4000, false,
               VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);

    uint32_t *tramp = (uint32_t *)trampoline;
    memcpy(tramp, prologue, sizeof(prologue));
    NJWriteAbsoluteJump(tramp + 4, (uint8_t *)target + 16);
    sys_icache_invalidate(tramp, 32);

    // 2. 把目标函数开头改写为跳向 replacement
    vm_address_t page = (vm_address_t)target & ~(vm_address_t)0xFFF;
    vm_protect(mach_task_self(), page, 0x4000, false,
               VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    NJWriteAbsoluteJump((uint32_t *)target, replacement);
    vm_protect(mach_task_self(), page, 0x4000, false,
               VM_PROT_READ | VM_PROT_EXECUTE);
    sys_icache_invalidate(target, 16);

    return (void *)trampoline;
}

#pragma mark - 优先转发给真实 Substrate

typedef void (*NJHookMessageExFn)(Class, SEL, IMP, IMP *);
typedef void *(*NJHookFunctionFn)(void *, void *, void **);

static void *NJLookUpRealSubstrate(const char *symbol) {
    void *addr = dlsym(RTLD_DEFAULT, symbol);
    if (addr == NULL) return NULL;
    // dlsym 可能拿到自己（正常情况本符号是 hidden，不会命中），再做一次排除
    return addr;
}

#pragma mark - 导出符号

NJ_HIDDEN
void MSHookMessageEx(Class _class, SEL sel, IMP imp, IMP *result) {
    static NJHookMessageExFn realImpl = NULL;
    static BOOL resolved = NO;

    NJ_gHookMessageCount++;

    if (!resolved) {
        resolved = YES;
        void *addr = NJLookUpRealSubstrate("MSHookMessageEx");
        if (addr && addr != (void *)&MSHookMessageEx) {
            realImpl = (NJHookMessageExFn)addr;
            NJ_gMode = 2;
            NSLog(@"[NJ] 使用进程内已有的 Substrate 实现: %p", addr);
        } else {
            NJ_gMode = 1;
            NSLog(@"[NJ] 未找到 Substrate，改用内置 MSHookMessageEx");
        }
    }

    if (realImpl) {
        realImpl(_class, sel, imp, result);
        return;
    }
    NJHookMessageExImpl(_class, sel, imp, result);
}

NJ_HIDDEN
void MSHookFunction(void *symbol, void *replace, void **result) {
    static NJHookFunctionFn realImpl = NULL;
    static BOOL resolved = NO;

    NJ_gHookFunctionCount++;

    if (!resolved) {
        resolved = YES;
        void *addr = NJLookUpRealSubstrate("MSHookFunction");
        if (addr && addr != (void *)&MSHookFunction) {
            realImpl = (NJHookFunctionFn)addr;
        }
    }

    if (realImpl) {
        realImpl(symbol, replace, result);
        return;
    }

    void *trampoline = NJHookFunctionImpl(symbol, replace);
    if (result) {
        // hook 失败时把 orig 指回原函数：调用方拿到的仍是原始行为，不会解引用空指针
        *result = trampoline ? trampoline : symbol;
    }
}
