//
//  iReadNoteTweak.m
//  爱阅记 5.3.0 — 去广告 / 永久会员 / 无限爱阅点
//
//  纯 Objective-C runtime hook，不依赖 CydiaSubstrate / Theos，
//  可在非越狱设备上由 LCSign 注入 dylib 后生效。
//
//  编译见同目录 Makefile / GitHub Actions workflow。
//

#import <Foundation/Foundation.h>
#import <objc/runtime.h>

#pragma mark - 通用 IMP

static BOOL IRRetYES(id self, SEL _cmd) { return YES; }
static BOOL IRRetNO(id self, SEL _cmd)  { return NO; }

// 带一个参数的 BOOL 方法（decHour: / isForceAd: 等），不读取参数
static BOOL IRRetYES1(id self, SEL _cmd, id arg) { return YES; }
static BOOL IRRetNO1(id self, SEL _cmd, id arg)  { return NO; }

static void IRVoid0(id self, SEL _cmd) {}
static void IRVoid1(id self, SEL _cmd, id arg) {}
static void IRVoid2(id self, SEL _cmd, id arg1, id arg2) {}

#pragma mark - 爱阅点：hook load 后注入巨额余额

static void (*origLoad)(id, SEL) = NULL;

static void IRLoadHook(id self, SEL _cmd) {
    if (origLoad) origLoad(self, _cmd);

    // BizManager 的爱阅点余额是 +0x10 处的一个 double（秒数）
    // 见反编译 BizManager::load / decHour: / save
    // ARC 下不允许 id -> char* 直接转换，先过 void* (__bridge) 再算偏移
    uintptr_t addr = (uintptr_t)(__bridge void *)self;
    double *balance = (double *)(addr + 0x10);
    *balance = 1.0e15;
}

#pragma mark - Hook 安装器

static void setImpl(Class cls, SEL sel, IMP imp, const char *types, BOOL instance) {
    if (!cls || !sel) return;
    Class target = instance ? cls : object_getClass(cls);
    Method m = class_getInstanceMethod(target, sel);
    if (m) {
        method_setImplementation(m, imp);
    } else {
        class_addMethod(target, sel, imp, types);
    }
}

// 类方法 + 实例方法都替换，避免搞错某方法是 + 还是 -
static void hookBoth(Class cls, SEL sel, IMP imp, const char *types) {
    setImpl(cls, sel, imp, types, YES);
    setImpl(cls, sel, imp, types, NO);
}

static void hookBOOL(Class cls, NSString *selName, BOOL value) {
    SEL sel = NSSelectorFromString(selName);
    IMP imp = value ? (IMP)IRRetYES : (IMP)IRRetNO;
    hookBoth(cls, sel, imp, "B@:");
}

static void hookBOOL1(Class cls, NSString *selName, BOOL value) {
    SEL sel = NSSelectorFromString(selName);
    IMP imp = value ? (IMP)IRRetYES1 : (IMP)IRRetNO1;
    hookBoth(cls, sel, imp, "B@:@");
}

static void hookVoid(Class cls, NSString *selName, NSUInteger argc) {
    SEL sel = NSSelectorFromString(selName);
    IMP imp;
    const char *types;
    switch (argc) {
        case 0: imp = (IMP)IRVoid0; types = "v@:";   break;
        case 1: imp = (IMP)IRVoid1; types = "v@:@";  break;
        default: imp = (IMP)IRVoid2; types = "v@:@@"; break;
    }
    hookBoth(cls, sel, imp, types);
}

#pragma mark - CloudKit 启动防崩溃

// 根因：重签后 Bundle ID 变更，CKContainer.defaultContainer 找不到
// iCloud.<新bundleid> 容器，loginForce: 里 fetchUserRecordID 触发 _os_crash。
// 只让 container 返回 nil：loginForce: 内部拿到 nil 后，
// [nil fetchUserRecordIDWithCompletionHandler:] 是 no-op，安全返回。
// 注意：绝不能 hook loginForce: 本身 —— 它返回对象，调用方会 retain 返回值，
// 用 void 实现会导致 retain 垃圾指针崩溃（这就是 v2 的闪退原因）。
static id IRContainerNil(id self, SEL _cmd) { return nil; }

// ---- 伪在线 / 伪登录：解锁所有依赖云端的付费功能 ----
// CurNetworkStatus 返回值: 0=无网 1=WiFi 2=蜂窝。返回 1 让所有网络闸门放行
static long long IRNetStatus(id self, SEL _cmd) { return 1; }
// isLogin 判断 +(0x48)==2，container=nil 永远到不了 2，这里直接给 YES
static id IRUserRecordName(id self, SEL _cmd) { return @"iReadLocalUser"; }
static id IRUserId(id self, SEL _cmd) { return @"iReadLocalUser"; }
// NTP 时间：离线拿不到，用系统时间兜底（爱阅点奖励/时长校验用）
static id IRNetDate(id self, SEL _cmd) { return [NSDate date]; }

// 版本标记（可通过 strings 校验 dylib 版本）
__attribute__((used)) static const char *kIRVersion = "IRTWEAK_V4_fake_online_unlock";

#pragma mark - 安装所有 hook

static void installHooks(void) {
    // ---- 0) 启动防崩溃 + 伪在线解锁 ----
    Class cloudMgr = objc_getClass("JxdCloudServerManager");
    if (cloudMgr) {
        SEL containerSel = NSSelectorFromString(@"container");
        Method cm = class_getInstanceMethod(cloudMgr, containerSel);
        if (cm) {
            IMP cur = method_getImplementation(cm);
            if (cur != (IMP)IRContainerNil) {
                method_setImplementation(cm, (IMP)IRContainerNil);
            }
        }
        hookBOOL(cloudMgr, @"isLogin", YES);
        Method urn = class_getInstanceMethod(cloudMgr, NSSelectorFromString(@"userRecordName"));
        if (urn) method_setImplementation(urn, (IMP)IRUserRecordName);
        Method uid = class_getInstanceMethod(cloudMgr, NSSelectorFromString(@"userId"));
        if (uid) method_setImplementation(uid, (IMP)IRUserId);
    }

    // 网络状态永真 -> BizManager::start / CheckOpenContentUI / isCanPurchase 全部放行
    Class net = objc_getClass("JxdNetSub");
    if (net) {
        Method nm = class_getInstanceMethod(net, NSSelectorFromString(@"CurNetworkStatus"));
        if (nm) method_setImplementation(nm, (IMP)IRNetStatus);
    }

    // NTP 时间永真 -> addReward 等时间校验不再因离线失败
    Class ntp = objc_getClass("JxdNtpClient");
    if (ntp) {
        Method nd = class_getInstanceMethod(ntp, NSSelectorFromString(@"netDate"));
        if (nd) method_setImplementation(nd, (IMP)IRNetDate);
    }

    // 付费内容闸门直接短路（分享/导出/复制不再弹购买）
    Class sdu = objc_getClass("ShareDataUnit");
    if (sdu) {
        hookVoid(sdu, @"CheckOpenContentUI", 0);
        hookVoid(sdu, @"OpenContentUI", 0);
    }

    // ---- 1) 永久会员 ----
    Class purchase = objc_getClass("PurchaseKit");
    hookBOOL(purchase, @"isValid",          YES);
    hookBOOL(purchase, @"isLifeTimeValid",  YES);
    hookBOOL(purchase, @"isValidRelease",   YES);
    hookBOOL(purchase, @"compatible",       YES);

    Class tran = objc_getClass("IAPTranInfo");
    hookBOOL(tran, @"isValid", YES);

    // ---- 2) 去广告 ----
    Class ad = objc_getClass("AdManager");
    hookVoid(ad, @"setup", 0);
    hookVoid(ad, @"onAppInitFinished", 0);
    hookVoid(ad, @"startFullScreen:", 1);
    hookBOOL(ad, @"hasFullScreen", NO);
    hookBOOL(ad, @"hasRewardVideo", NO);

    Class biz = objc_getClass("BizManager");
    hookVoid(biz, @"checkOpenFullScreenAd", 0);

    Class cfg = objc_getClass("CloudBizConfig");
    hookBOOL1(cfg, @"isForceAd:", NO);

    Class bizUI = objc_getClass("BizUI");
    hookVoid(bizUI, @"ShowPaidOnly", 0);
    hookVoid(bizUI, @"ShowPaidOr68:", 1);
    hookVoid(bizUI, @"ShowMust:", 1);

    // ---- 3) 无限爱阅点 ----
    // decHour: 恒返回 YES 且不扣减 -> 永不扣点
    hookBOOL1(biz, @"decHour:", YES);

    // load 后把余额写成巨额 -> UI 显示 / 本地存储都是无限
    // 用实现指针守卫：installHooks 会被调用多次，避免把 origLoad 指向自身造成递归
    SEL loadSel = NSSelectorFromString(@"load");
    Method loadM = class_getInstanceMethod(biz, loadSel);
    if (loadM) {
        IMP cur = method_getImplementation(loadM);
        if (cur != (IMP)IRLoadHook) {
            origLoad = (void (*)(id, SEL))cur;
            method_setImplementation(loadM, (IMP)IRLoadHook);
        }
    }
}

__attribute__((constructor)) static void iReadNoteTweakInit(void) {
    @autoreleasepool {
        // 三重保险：注入场景下不同 iOS / 注入方式导致类注册时机不同。
        // installHooks 是幂等的（load 有实现指针守卫），重复调用安全。
        installHooks();

        // 下一次 runloop 再补一次
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.3 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            @autoreleasepool { installHooks(); }
        });

        // App 启动完成时再补一次（最稳妥，此时所有类必然已注册）
        [[NSNotificationCenter defaultCenter]
            addObserverForName:@"UIApplicationDidFinishLaunchingNotification"
                        object:nil queue:[NSOperationQueue mainQueue]
                    usingBlock:^(NSNotification *note) {
            @autoreleasepool { installHooks(); }
        }];
    }
}
