# 爱阅记 iReadNote 5.3.0 — 广告任务与会员权益逆向分析结论

分析对象：`爱阅记_5.3.0.ipa`，SHA-256 `6e166c076c9eee7f64c8ea95f31694edd69f4fbdc30162f0a368cad70a0dded5`
主二进制：`iReadNote`（arm64 Mach-O，35.5MB），`cryptid=0`（已解密砸壳，静态证据有效）
Bundle ID：`jxd.devapp.iReadNote` / 版本 5.3.0 (build 277) / iOS 17.0+
流水线：GitHub Actions `macos-15`（Apple Silicon M1），run `44042788478`

## 一、证据分级

| 级别 | 含义 |
|---|---|
| 【观察】 | 直接从 shipped artifact 读取（字符串、selector、plist、Mach-O 结构），可信 |
| 【推断】 | 基于观察的架构判断，需动态验证 |
| 【未知】 | 静态无法确定，需反编译函数体或运行时抓包 |

## 二、会员与广告体系结构【观察】

### 2.1 双轨会员制（来自本地化文案 lmsg_purchInfo / lmsg_bizDetail）
- **买断制**：一次扣费，永久有效（`lmsg_paidLifetimeOnly`「永久会员」）
- **自动订阅**：连续包月(1月)/包季(3月)/包年(12月)，到期前24h自动续费
- **爱阅点（软权益）**：免广告 + 开启部分功能，门槛 `付费 或 爱阅点>68`
  - 首次安装赠点；日常广告、激励视频广告、每推荐一人各赠点
  - 每小时消耗 1 点（无论是否使用）；为 0 触发日常广告
  - 爱阅点低于阈值时，每年强制广告数量 ≤ 12 次

### 2.2 账户与数据归属
- 账户系统基于 **iCloud/CloudKit**，无需注册登录（`lmsg_bizShortIdFailed`）
- CloudKit container / Team ID：`iCloud.jxd.dev`、`group.jxd.dev`、`A278GWKB7R.jxd.dev`
- 推荐人机制：`iReadNote://referee/%@`，双向发点（`lmsg_bizShortIdOK`）

### 2.3 关键类与 selector【观察】
- `JxdStoreKit.swift`（自研 StoreKit 封装）：
  - `fetchCurEntitlements:`、`fetchAppTransactionID:`、`purchaseWithProductID:completion:`、
    `appStoreReceiptURL`、`buyProduct:`、`preparePurchase:`
  - 日志字符串：`JxdStoreKit: 交易验证失败`、`权益验证失败`、`历史交易验证失败`、
    `获取 appTransactionID 失败`、`未找到产品`
- 状态字段：`vip_type`、`ownershipType`、`memberReward`、`is_member`、`purchaseDateMS`、`InAppPurchaseDeviceID`
- 广告：`AdManager`、`BuRewardAds`（穿山甲）、`GgRewardAds`（AdMob）、
  `pauseRewardFullLinkByStoreKitOpen`（付费校验与广告联动）
- JS Bridge：`buJSB3_send_temai_product_idsWithViewModel:`、`jsCallNative_send_temai_product_idsWithParams:`
  （H5 广告落地页把产品 ID 传给原生）

## 三、触发条件与校验流程【推断】

1. **付费会员判定**：App 启动/进入会员页 → `JxdStoreKit` 读取 `appStoreReceiptURL`，
   拉取 `appTransactionID`，调 `fetchCurEntitlements:` → 解析出 `ownershipType`/`vip_type`
   → 决定免广告与功能解锁。权威数据来自 Apple，客户端无法伪造有效收据。
2. **爱阅点判定**：读 CloudKit 私有库中的点数与账户短ID，结合本地时间做每小时扣减。
   点数 > 68 视为等效付费。此处是客户端/云端的混合判定。
3. **广告任务**：`AdManager` 加载激励视频 → SDK 回调「播放完成」→ 客户端发放点数。
   发点动作在客户端，但点数持久化依赖 CloudKit 账户。

## 四、客户端 vs 服务端职责【推断】

| 职责 | 位置 | 可否被客户端篡改 |
|---|---|---|
| 真实付费权益（买断/订阅） | Apple App Store 收据 | 否（需有效 Apple 签名收据） |
| 账户身份/推荐关系/点数账本 | iCloud CloudKit 私有库 | 受 CloudKit 权限约束 |
| 会员状态呈现、功能开关 | 客户端本地字段 | 是（但只是界面，非权威） |
| 激励视频播放与完成回调 | 客户端 + 广告 SDK | 回调可伪造，但发点落 CloudKit |

## 五、对「跳过广告领会员 / 永久会员」的结论性评估

- **改本地字段（vip_type/is_member/ownershipType）**：只能改本机界面显示，属于自欺欺人；
  不产生 Apple 收据，不改变 CloudKit 账本，重装/更新即失效。**不构成可行方案。**
- **伪造广告完成回调骗取爱阅点**：回调在客户端，理论上可 hook，但点数写入依赖 CloudKit 账户，
  且阈值仍是「等效功能解锁」而非真会员；存在账号风控与同步覆盖风险。**不稳定、非永久。**
- **伪造 StoreKit 收据 / appTransactionID 拿永久会员**：Apple 收据有签名与服务端校验路径
  （`交易验证失败`/`权益验证失败` 日志说明存在验证环节），本地伪造无法通过。**不可行。**
- **真正获得永久会员**：仅 `买断制` 一次购买这一条合法路径。

**一句话结论**：本 App 的付费权益以 Apple 收据 + CloudKit 为信任根，客户端只做呈现与广告回调；
「跳过广告领会员」最多改本机界面，「获得永久会员」在静态层面无可利用的客户端缺陷。
两者都不构成可交付的攻击方案。

## 六、Ghidra 函数体级证据（run 44047092553，success，artifact `14312658883`）

最终流水线全绿，导出 **565 个函数伪代码**，其中 156 个为业务自有符号。核心校验函数已坐实：

- **PurchaseKit::isLifeTimeValid**（`1003fef04`）【观察】：遍历交易集合，对每笔交易连续做三项判定
  （类型检查 → 状态==1 → 标志位），任一命中即返回 true。**永久会员来自遍历历史交易，不是本地布尔开关。**
- **PurchaseKit::handleVerifyTrans / onVerifyFinished**（`1003ff7a8`/`1003ffcc8`）【观察】：
  验证是异步状态机（`dispatch_async`、状态码 6、遍历验证结果），非一次性本地判断。
- **PurchaseKit::startAccountVerify**（`1004007b8`）【观察】：直接调用 `JxdStoreKit` 单例，账户校验入口即 StoreKit 封装。
- **JxdStoreKit::fetchCurEntitlements / fetchAppTransactionID / getTransactionHistoryWithCompletion**（Swift）【观察】：
  权益读取走 StoreKit 的 entitlement 与交易历史 API。
- **CloudPurchaseConfig::isNeedVerifEnv**（`10015a998`）【观察】：含魔法数 `0x135288a` 与 `_envVerifyDate`、
  NSDate 比较，**存在环境校验机制**（配合 `JxdStoreKit::isProduction`/`prepareEnv`），用于区分生产/沙盒、抵御伪造 IAP。
- **BuRewardAds::nativeExpressRewardedVideoAdServerRewardDidSucceed_verify:**（`1002aed38`）【观察】：
  激励视频发奖带 `verify` 参数，广告服务端参与奖励校验。

这把第五节大部分判断从【推断】升级为【观察】：校验为**交易驱动 + 异步状态机 + 环境校验 + 广告服务端 verify** 的多层结构，
不存在"改一个本地标志就永久免费"的单点。

## 七、诚实标注的未知
- Objective-C/Swift 运行时调用在 Ghidra 里被脱符号化为 `FUN_1016xxxxx`，具体某个 `FUN_` 对应的
  StoreKit API 需结合 xrefs 或动态 hook 才能一一对应；本报告对控制流结构的解读为【推断】，对"遍历交易/异步验证/环境校验"的存在为【观察】。
- 未做运行时抓包与动态 hook（CI 静态环境无法执行 App）；`fetchCurEntitlements` 的最终权益是否上报自建服务端，
  静态证据只显示 CloudKit + StoreKit，未发现独立 HTTP 会员校验接口（`jxd.dev` 域名下未见会员 API）。
