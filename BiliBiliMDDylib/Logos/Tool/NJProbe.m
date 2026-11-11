//
//  NJProbe.m
//  加载探针：一次注入即可判断插件到底走到了哪一步。
//
//  三种可能的结果，对应三个完全不同的排查方向：
//    1. 弹窗根本没出现        → dylib 没被 dyld 加载，问题在注入环节
//    2. 弹窗出现，hook 计数 0 → dylib 加载了但 %ctor 没跑（构造器被裁剪/异常）
//    3. 弹窗出现，计数 > 0    → hook 已注册，问题在类名/方法名与当前 B 站版本不匹配
//
//  正式版里把 NJ_PROBE_ENABLED 关掉或删掉本文件即可。
//

#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <unistd.h>
#import "NJCommonDefine.h"

/// 由 NJSubstrateCompat.m 提供
extern int NJSubstrateMode(void);
extern int NJHookMessageCount(void);
extern int NJHookFunctionCount(void);

static UIWindow *NJProbeKeyWindow(void) {
    UIWindow *keyWindow = nil;
    if (@available(iOS 13.0, *)) {
        for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
            if (![scene isKindOfClass:[UIWindowScene class]]) continue;
            if (scene.activationState != UISceneActivationStateForegroundActive) continue;
            for (UIWindow *w in ((UIWindowScene *)scene).windows) {
                if (w.isKeyWindow) {
                    keyWindow = w;
                    break;
                }
            }
            if (keyWindow) break;
        }
    }
    if (!keyWindow) {
        keyWindow = UIApplication.sharedApplication.keyWindow;
    }
    return keyWindow;
}

static void NJProbeWriteLog(NSString *text) {
    NSString *path = @"/var/mobile/Library/Caches/nj_probe.txt";
    NSString *full = [NSString stringWithFormat:@"%@\n", text];
    [full writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:NULL];
    NSLog(@"[NJ-PROBE] %@", text);
}

/// 读总开关的实际值：所有 hook 的 %ctor 都以它为门禁，
/// 一旦为 NO，12 个功能会全部静默失效。
static NSString *NJProbeMasterSwitchText(void) {
    @try {
        BOOL on = NJ_MASTER_SWITCH_VALUE;
        return on ? @"开启" : @"已关闭 ← 这就是所有 hook 失效的原因";
    } @catch (__unused NSException *e) {
        return @"读取异常";
    }
}

__attribute__((constructor))
static void NJProbeInit(void) {
    NJProbeWriteLog([NSString stringWithFormat:@"dylib loaded, pid=%d, time=%@",
                     getpid(), [NSDate date]]);

    // 等主界面准备好再弹窗；构造器执行时 UI 还没起来
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(6 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        UIWindow *window = NJProbeKeyWindow();
        if (!window || !window.rootViewController) {
            NJProbeWriteLog(@"已加载，但 6 秒内没拿到 key window，无法弹窗");
            return;
        }

        NSString *appVersion = [[NSBundle mainBundle]
            objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"?";
        BOOL hasYYCache = NSClassFromString(@"YYCache") != nil;

        int mode = NJSubstrateMode();
        NSString *modeText;
        if (mode == 2) {
            modeText = @"转发给进程内 Substrate";
        } else if (mode == 1) {
            modeText = @"内置实现";
        } else {
            modeText = @"从未被调用";
        }

        NSString *message = [NSString stringWithFormat:
            @"B站版本：%@\n"
            @"总开关：%@\n"
            @"方法 hook 注册：%d 次\n"
            @"函数 hook 注册：%d 次\n"
            @"hook 入口：%@\n"
            @"YYCache：%@",
            appVersion,
            NJProbeMasterSwitchText(),
            NJHookMessageCount(),
            NJHookFunctionCount(),
            modeText,
            hasYYCache ? @"可用" : @"缺失（设置项全部失效）"];

        NJProbeWriteLog([message stringByReplacingOccurrencesOfString:@"\n" withString:@" | "]);

        UIAlertController *alert =
            [UIAlertController alertControllerWithTitle:@"BiliBiliMD 探针"
                                                message:message
                                         preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"知道了"
                                                  style:UIAlertActionStyleDefault
                                                handler:nil]];
        [window.rootViewController presentViewController:alert animated:YES completion:nil];
    });
}
