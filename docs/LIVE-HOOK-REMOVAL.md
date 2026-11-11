# 摘除直播间内全部 Hook（Live Hook Removal）

> 本文记录对本项目 **3.1.0 成品 dylib** 的一次二进制级改动：移除直播间内全部 hook，
> 让直播间的返回键、UP 主头像/昵称、在线人数、吊坠等元素恢复原生显示，
> **其余所有功能（启动页 / 信息流 / 详情页广告过滤、3 倍速等）保持原样**。

---

## 1. 为什么要改成品而不是改源码

本仓库的源码对应 **2.6.1**，而实际在用的成品是 **3.1.0**，中间隔了一个大版本：

| 项目 | 源码（本仓库） | 实际成品 |
|---|---|---|
| 版本 | 2.6.1 | **3.1.0** |
| 版本适配上限 | `NJAppCompatible_8_76_0_Handler`（8.76.0） | 3.1.0 内置 |
| 目标 B 站版本 | 8.x | **9.18.0** |

用 2.6.1 源码重新编译后注入 9.18.0 的 B 站，会出现**插件看似运行、hook 看似注册，但全部无效**的现象：

- 加载探针显示「方法 hook 注册：53 次」，说明 `MSHookMessageEx` 确实被调用
- 但 `%hook` 的目标类/方法在 9.18.0 中已改名或不存在，注册静默失败
- 表现为：广告回来了，而直播间的吊坠也没有恢复

**结论：源码路线在这个版本组合下不可用，必须直接在成品上做精确摘除。**

---

## 2. 定位过程

### 2.1 解析 Mach-O 结构

```
filetype      = 6 (MH_DYLIB)
architecture  = arm64
install_name  = /Library/MobileSubstrate/DynamicLibraries/BiliBiliTweak.dylib
platform      = iOS, minos 13.0
__mod_init_func = 17 项          ← 17 个 Logos 构造函数
```

### 2.2 找出引用直播类名的构造函数

遍历 `__TEXT,__text`，扫描所有 `ADRP` + `ADD` 组合，还原出每个函数引用的 C 字符串地址。结果：

```
构造函数 0x00d99c : 21 处引用直播相关类名   ← 唯一命中
其余 16 个构造函数 : 0 处
```

命中的 21 个类名覆盖了直播间内的全部被 hook 对象：

```
BBLiveRevenueCardsContentView     收入面板、礼物面板
BBLiveVerticalTopBar              顶部栏（用户排名入口）
BBLiveVerticalCenterBar           吊坠容器（返回键 / 头像 / 在线人数）
BBLiveReserveButton               预约按钮
BBLiveDetailAdView                直播详情页广告
BBLChronFunctionCard              弹幕下功能卡
BBLiveTopRightEntranceManager     右上角入口（观赛、更多直播）
BBLOLActivityView                 右下角活动
BBLiveGiftAnimationView           礼物动画（SVGA / MP4 / Spine）
BBLiveRankListView                人气榜、分区榜、混合榜
LynxView                          排行榜 Lynx 渲染容器
...                               共 21 个
```

### 2.3 函数结构

反汇编 `0x00d99c`，确认它是标准的「开关判断 + 批量注册」结构：

```asm
0x00d99c  stp  x24, x23, [sp, #-0x40]!      ; 保存栈帧
0x00d9a0  stp  x22, x21, [sp, #0x10]
0x00d9a4  stp  x20, x19, [sp, #0x20]
0x00d9a8  stp  x29, x30, [sp, #0x30]
0x00d9ac  mov  x29, sp
0x00d9b0  ...                                ; 读 NJ_MASTER_SWITCH_KEY
0x00d9e0  bl   #0x3bb40                      ; 读取总开关
0x00d9e4  cbz  w0, #0xda58                   ; 开关关闭 → 直接返回
0x00da7c  adrp x0, #0x41000                  ; ← hook 注册起点
0x00da80  add  x0, x0, #0xe04                ; "BBLiveRevenueCardsContentView"
0x00da84  bl   #0x3a00c                      ; objc_getClass
...
0x00da58  ldp  x29, x30, [sp, #0x30]         ; 栈恢复 + 返回
0x00da5c  ldp  x20, x19, [sp, #0x20]
0x00da60  ldp  x22, x21, [sp, #0x10]
0x00da64  ldp  x24, x23, [sp], #0x40
0x00da68  ret
```

注意 `0x00d9e4` 处已有 `cbz w0, #0xda58`：**总开关关闭时，函数原本就是直接跳到 `0xda58` 返回**。
这给了我们一个现成的、编译器生成的安全退出路径。

---

## 3. 改动内容

### 3.1 代码：1 条指令，4 字节

把 `0x00da7c` 处的 `adrp` 改成无条件的 `b`：

```diff
- 0x00da7c  a0 01 00 90   adrp x0, #0x41000
+ 0x00da7c  f7 ff ff 17   b    #0xda58
```

`b` 的编码：`0x17 << 24 | (imm26 & 0x03FFFFFF)`，`imm26 = (0xda58 - 0xda7c) / 4 = -9`。

效果：构造函数在读完总开关后立即跳转到函数尾部的栈恢复序列返回，
**21 个直播类、20 余条 hook 全部不注册**，且栈帧完整平衡，不会破坏调用者状态。

### 3.2 签名：2 个 page hash

这版 dylib 是 **SHA1 + SHA256 双 CodeDirectory** 的 ad-hoc 签名，`pageSize = 4096`，共 160 页。

改动落在第 13 页（`0xd000 - 0xdfff`），因此需要重算该页的两种哈希：

| CodeDirectory | 槽位 | 偏移 | 变化 |
|---|---|---|---|
| SHA1 | slot 13 | `0x9f38c` | 已更新（20 字节） |
| SHA256 | slot 13 | `0xa01dc` | 已更新（32 字节） |

签名结构（`SuperBlob` → `CodeDirectory` → `Requirements`）完整保留，
`nSpecialSlots` / `nCodeSlots` / `codeLimit` / identifier 均未改动。

**全量复核：160 页，两种哈希算法，不匹配页数 0。**

### 3.3 改动总量

```
文件大小      660,560 字节 → 660,560 字节（不变）
差异字节数    56 字节
  ├─ 0xda7c - 0xda7f    4 字节   代码
  ├─ 0x9f38c - 0x9f39f  20 字节  SHA1 page hash
  └─ 0xa01dc - 0xa01fb  32 字节  SHA256 page hash
```

其余 **660,504 字节与原版完全一致**。

---

## 4. 产物

```
dist/BiliBiliTweak-3.1.0-nolive.dylib
SHA256: c8b318f456ab560d3d2d6ba58fb66aea049f3025a5a7e5abc98641cd58bc7b3d
大小:   660,560 字节 (646 KB)
架构:   arm64
```

### 注入方法

1. TrollFools 中**先移除** B 站上已有的旧插件（避免同名 dylib 残留）
2. 注入本文件
3. **完全杀掉 App** 再启动（不要只热重载）

TrollFools 注入时会自行重签，覆盖本文件的 ad-hoc 签名属正常现象，重签后同样有效。

---

## 5. 验收标准

| 观察位置 | 期望结果 |
|---|---|
| 直播间顶部 | 返回键、UP 主头像、昵称、在线人数**全部恢复** |
| 直播间内 | 礼物面板、各类榜单、预约弹窗、活动卡均为**原生状态** |
| 首页推荐流 | **广告仍被过滤**（这是判断插件其余功能正常的关键） |
| 视频详情页 / 动态 / 搜索 | 广告行为与 3.1.0 原版一致 |

> 判断要点：**首页广告若仍被过滤，说明插件本体运行正常**，
> 本次改动只影响了直播间那一个构造函数。

---

## 6. 附：本仓库中已废弃的实验代码

以下文件是为「从 2.6.1 源码重编」这条路线添加的实验代码，
在确认源码版本过旧后已不再使用，保留仅为记录：

| 文件 | 用途 | 状态 |
|---|---|---|
| `BiliBiliMDDylib/Logos/Tool/NJSubstrateCompat.m` | 自包含 `MSHookMessageEx` / `MSHookFunction` 实现，解决非越狱环境缺少 CydiaSubstrate 的问题 | 已废弃 |
| `BiliBiliMDDylib/Logos/Tool/NJProbe.m` | 加载探针，弹窗显示总开关、hook 注册计数、substrate 来源 | 已废弃（但当时确实定位到了问题） |
| `.github/workflows/build-dylib.yml` | GitHub Actions 云端编译 2.6.1 源码 | 已废弃 |

这些代码**不会**影响 `dist/` 下的成品，成品是独立修改的 3.1.0 二进制。

如果后续上游把源码更新到 3.1.0 / 9.x 适配，可以回到源码路线，
届时只需在 `NJLiveDetailAd.xm` 的 `%ctor` 中不调用 `%init(App)` 即可。
