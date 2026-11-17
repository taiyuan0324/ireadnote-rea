// iReadNote 5.3.0 tweak - ad-free / lifetime VIP / unlimited points
// Pure Objective-C runtime hook, no CydiaSubstrate needed.
#import <Foundation/Foundation.h>
#import <objc/runtime.h>

static BOOL IRRetYES(id self, SEL c) { return YES; }
static BOOL IRRetNO(id self, SEL c)  { return NO; }
static BOOL IRRetYES1(id self, SEL c, id a) { return YES; }
static BOOL IRRetNO1(id self, SEL c, id a)  { return NO; }
static void IRVoid0(id self, SEL c) {}
static void IRVoid1(id self, SEL c, id a) {}
static void IRVoid2(id self, SEL c, id a, id b) {}

static void (*origLoad)(id, SEL) = NULL;
static void IRLoadHook(id self, SEL c) {
    if (origLoad) origLoad(self, c);
    double *balance = (double *)((char *)self + 0x10);
    *balance = 1.0e15;
}

static void setImpl(Class cls, SEL sel, IMP imp, const char *types, BOOL instance) {
    if (!cls || !sel) return;
    Class target = instance ? cls : object_getClass(cls);
    Method m = class_getInstanceMethod(target, sel);
    if (m) method_setImplementation(m, imp);
    else class_addMethod(target, sel, imp, types);
}
static void hookBoth(Class cls, SEL sel, IMP imp, const char *types) {
    setImpl(cls, sel, imp, types, YES);
    setImpl(cls, sel, imp, types, NO);
}
static void hookBOOL(Class cls, NSString *n, BOOL v) {
    hookBoth(cls, NSSelectorFromString(n), v ? (IMP)IRRetYES : (IMP)IRRetNO, "B@:");
}
static void hookBOOL1(Class cls, NSString *n, BOOL v) {
    hookBoth(cls, NSSelectorFromString(n), v ? (IMP)IRRetYES1 : (IMP)IRRetNO1, "B@:@");
}
static void hookVoid(Class cls, NSString *n, NSUInteger argc) {
    IMP imp; const char *types;
    switch (argc) {
        case 0: imp = (IMP)IRVoid0; types = "v@:"; break;
        case 1: imp = (IMP)IRVoid1; types = "v@:@"; break;
        default: imp = (IMP)IRVoid2; types = "v@:@@"; break;
    }
    hookBoth(cls, NSSelectorFromString(n), imp, types);
}

static void installHooks(void) {
    Class purchase = objc_getClass("PurchaseKit");
    hookBOOL(purchase, @"isValid", YES);
    hookBOOL(purchase, @"isLifeTimeValid", YES);
    hookBOOL(purchase, @"isValidRelease", YES);
    hookBOOL(purchase, @"compatible", YES);
    Class tran = objc_getClass("IAPTranInfo");
    hookBOOL(tran, @"isValid", YES);

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

    hookBOOL1(biz, @"decHour:", YES);
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
        installHooks();
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.3 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ @autoreleasepool { installHooks(); } });
        [[NSNotificationCenter defaultCenter]
            addObserverForName:@"UIApplicationDidFinishLaunchingNotification"
                        object:nil queue:[NSOperationQueue mainQueue]
                    usingBlock:^(NSNotification *n) { @autoreleasepool { installHooks(); } }];
    }
}
