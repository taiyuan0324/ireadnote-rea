# 爱阅记 iReadNote 5.3.0 — 全量逆向分析报告

> 分析对象：`爱阅记_5.3.0.ipa`
> SHA-256：`6e166c076c9eee7f64c8ea95f31694edd69f4fbdc30162f0a368cad70a0dded5`
> 主二进制 SHA-256：`243a5409a432f301552759e39a41cbcb9ab6a8d9e9677a7e611b454fbfacbf05`
> 分析环境：GitHub Actions `macos-15`（Apple Silicon M1）+ Ghidra 12.1.4（自编译 arm64 反编译器）+ 便携 Python
> 流水线仓库：`https://github.com/taiyuan0324/ireadnote-rea`（私有）

---

## 0. 结论先行：`jxd.dev` 不是 API 域名

经对主二进制、11 个 Framework、1 个 App Extension、全部资源文件做全量字符串/URL/host 扫描（57 个文件、90 个唯一 host、30 条 API 风格路径）：

> **`jxd.dev` 在二进制中只以三种身份出现，均非 HTTP 服务端：**
> 1. `jxd.devapp.iReadNote` —— Bundle Identifier
> 2. `iCloud.jxd.devapp.iReadNote` —— CloudKit 容器标识
> 3. `group.jxd.devapp.files` —— App Group 标识
>
> **不存在 `https://*.jxd.dev/...` 形式的会员/订阅/VIP HTTP 接口。** 之前的 `network_endpoints.txt` 中出现的 `jxd.dev` 是正则把 bundle id 截断所致，已在本报告中纠正。

因此"jxd.dev 会员 API"这一前提不成立。会员数据的真实通路是 **Apple StoreKit + iCloud CloudKit**，详见第 5、6 节。

---

## 1. 应用基本信息

| 项 | 值 | 证据 |
|---|---|---|
| 显示名 | 爱阅记 | Info.plist `CFBundleName` |
| Bundle ID | `jxd.devapp.iReadNote` | Info.plist |
| 版本 / Build | 5.3.0 / 277 | Info.plist |
| 可执行文件 | `iReadNote` | Info.plist `CFBundleExecutable` |
| 架构 | arm64（单架构 Mach-O） | Mach-O header `cputype=0x0100000c` |
| 二进制大小 | 35,534,352 B（≈33.9MB） | summary.json |
| 加密状态 | `cryptid=0`（已解密/砸壳） | `LC_ENCRYPTION_INFO_64` |
| 最低 iOS | 17.0 | Info.plist |
| Team ID | `A278GWKB7R` | 嵌入 entitlements |
| URL Scheme | `iReadNote://`（URLName `icc.one.iReadNote`） | Info.plist `CFBundleURLTypes` |
| ATS | `NSAllowsArbitraryLoads = true`（放行明文 HTTP） | Info.plist |

Mach-O 结构：60 个 section，`__TEXT` 0x1be4000、`__DATA_CONST` 0x190000、`__DATA` 0x32c000、`__LINKEDIT` 0x1e0000。

---

## 2. 权限与组件

### 2.1 嵌入 entitlements（`__TEXT` 内嵌 plist）

```
com.apple.developer.icloud-container-identifiers = [iCloud.jxd.devapp.iReadNote]
com.apple.developer.icloud-services             = [CloudKit]
com.apple.developer.icloud-container-environment = Production
com.apple.developer.team-identifier             = A278GWKB7R
com.apple.security.application-groups           = [group.jxd.devapp.files]
aps-environment                                 = production
application-identifier                          = A278GWKB7R.jxd.devapp.iReadNote
```
→ 仅使用 **CloudKit**（未启用 CloudKit 的 iCloud Documents），启用 APNs 生产推送，有 App Group 供扩展共享。

### 2.2 隐私用途描述（Info.plist）

| Key | 文案摘要 | 用途 |
|---|---|---|
| `NSUserTrackingUsageDescription` | 允许跟踪以提供个性化服务及广告 | ATT / 广告归因 |
| `NSPhotoLibraryUsageDescription` | 图片可用于书籍封面或阅读背景 | 相册 |
| `NSFaceIDUsageDescription` | 打开加锁的分组或书籍 | 生物识别 |

### 2.3 隐私清单 `PrivacyInfo.xcprivacy`

- `NSPrivacyTracking = false`，`NSPrivacyCollectedDataTypes = []`，`NSPrivacyTrackingDomains = []`
- 声明使用的 Required-Reason API：`SystemBootTime`(35F9.1)、`FileTimestamp`(DDA9.1/C617.1/3B52.1)、`DiskSpace`(7D9E.1/E174.1)、`UserDefaults`(CA92.1)

### 2.4 组件清单

- **App Extension**：`ImportAction.appex`（`com.apple.ui-services`，MainStoryboard `MainInterface`）
  激活规则：支持 1–999 个附件、最多 999 图片/文件、支持文本；用于「拷贝到爱阅记」导入书籍。
- **Framework（11 个，均为火山引擎 TTSDK 播放链路依赖）**：
  `TTFFmpeg`、`TTSDKCore`、`TTSDKLiveBase`、`TTSDKLivePlayerLite`、`TTSDKLivePullVolcLog`、
  `TTSDKPlayerCoreLiveLite`、`TTSDKReachability`、`TTSDKStrategyLite`、`TTSDKTTFFmpegLiveLite`、
  `TTSDKVolcLog`、`VolcBaseLog`
- **SDK Bundle**：`CSJAdSDK.bundle`（穿山甲，含 `bu_dynamic_default.json` 等 UGen 素材）、`GoogleMobileAdsResources.bundle`
- **其他 Bundle**：`FluidAudio_LuxTtsG2pResources.bundle`、`PLzmaSDK_Privacy.bundle`

---

## 3. 静态代码结构

| 指标 | 数量 | 来源 |
|---|---|---|
| Objective-C 类名 | 4,759 | `__objc_classname` |
| ObjC selector / 方法名 | 71,080 | `__objc_methname` |
| C 字符串 | 12,354 | `__cstring` |
| 全二进制 ASCII 字符串 | 131,808 | 扫描 |
| 本地化条目 | 5,924 | 各 `*.lproj/Localizable.strings`（bplist） |
| Ghidra 识别函数总数 | 110,192 | `decompiled/index.csv` |
| 已导出伪代码函数 | 565 | `decompiled/*.c`（156 个业务符号） |

**业务自有命名空间**：`Jxd*`（约 200+ 类）。核心分层：
- 会员/支付：`PurchaseKit`、`CloudPurchaseConfig`、`PurchaseVC`、`IAPTranInfo`、`JxdStoreKit`(Swift)、`JxdIapProduct`、`JxdIapTransaction`、`PurchaseCompatible`
- 云端：`JxdCloudServerManager`（CloudKit 封装）、`JxdCloudUser`、`JxdCloudConfigBasic`、`JxdCloudSynManager`、`JxdCloud*Record`
- 网络：`JxdHttp`/`JxdHttpConfig`/`JxdHttpFetchs`（通用 HTTP 客户端，供书源/WebDAV）、`JxdNetSub`（网络探测）、`JxdNtpClient`（NTP）
- 广告：`AdManager`、`BuRewardAds`（穿山甲）、`GgRewardAds`（AdMob）、`VADateInfo`、`BizAdDateInfo`
- 第三方：`CSJ*`/`BU*`/`ABU*`（穿山甲/聚合）、`GAD*`（AdMob）、`FluidAudio*`（本地 TTS）

---

## 4. 关键业务逻辑

### 4.1 会员制式（本地化文案坐实）

- **买断制**：一次扣费，永久有效（`lmsg_paidLifetimeOnly`）
- **自动订阅**：连续包月/包季/包年，到期前 24h 自动续费（`lmsg_purchInfo`）
- **爱阅点（软权益）**：`付费 或 爱阅点 > 68` 解锁功能；每小时 -1 点（无论是否使用）；为 0 触发日常广告；低于阈值时每年强制广告 ≤12 次（`lmsg_bizDetail`）
- 点数来源：首次安装、日常广告、激励视频广告、每推荐一人（`lmsg_bizDetail` / `lmsg_bizShortIdOK`）
- 推荐机制：`iReadNote://referee/%@`，双向发点

### 4.2 购买参数（`CloudPurchaseConfig::resetDefault`，地址 0x10015a910）

```
verifySpace      = 0x69780 = 432000 秒 = 5 天   (复验间隔)
maxActiveDevCount= 3                            (最多 3 台活跃设备)
envVerifyDate    = 0x13528a1                    (环境校验基准日期)
_products        = NSConstantArray (产品列表，运行时/云端填充)
_tipIds          = NSConstantArray
```

### 4.3 会员判定链（Ghidra 伪代码，均为【观察】）

| 函数 | 地址 | 行为 |
|---|---|---|
| `PurchaseKit::isLifeTimeValid` | 0x1003fef04 | 遍历交易集合，对每笔连续判定（类型→状态==1→标志位），任一命中即 true |
| `PurchaseKit::verifyTrans:` | 0x1003ff884 | 按索引与本地交易数比对，命中则置状态 5/6，发 `CloudPaid` 通知 |
| `PurchaseKit::onVerifyTrans:info:status:` | 0x1003ffb34 | 状态机（0→3、6→2、其余→4）；随后调用 `JxdNtpClient` 校准网络时间 |
| `PurchaseKit::handleVerifyTrans` | 0x1003ff7a8 | 异步分发（`dispatch_async`），状态码 6 进入验证 |
| `PurchaseKit::startAccountVerify` | 0x1004007b8 | 直接调用 `JxdStoreKit` 单例，账户校验入口 |
| `PurchaseKit::isCanPurchase` | 0x1003fe6a0 | 检查 `JxdCloudServerManager` 登录态 + `JxdNetSub`（IsProxy/IsVPN）；不满足则弹 `AlertHelp` |
| `CloudPurchaseConfig::isNeedVerifEnv` | 0x10015a998 | 与 `_envVerifyDate`、NSDate 比较，决定是否需要环境复验 |
| `PurchaseKit::BeenCloudPaidSubs_NoSyn` | 0x1003fd2a8 | 读 **NSUserDefaults**（本地缓存标记，`NoSyn`=不同步） |
| `PurchaseKit::loadInfo` / `transFile` | 0x100400470 / 0x1004000cc | 交易 JSON 落 `Application Support`（目录常量 0xe=14），`NSJSONSerialization` 读写 |

**多层防篡改**：StoreKit 交易（Apple 签名 JWS）+ 本地交易文件 + NSUserDefaults 标记 + **NTP 网络时间**（防改系统时间续期）+ **代理/VPN 探测**（`JxdNetSub::IsProxy/IsVPN`）+ 环境复验间隔 5 天 + 设备数上限 3。

### 4.4 广告与发奖

| 类/函数 | 行为 |
|---|---|
| `AdManager` | 广告总调度 |
| `BuRewardAds::loadAd` / `nativeExpressRewardedVideoAdServerRewardDidSucceed:verify:` | 穿山甲激励视频加载与**带 verify 的服务端奖励回调** |
| `GgRewardAds::loadAd` / `handlePresent` | AdMob 激励视频 |
| `VADateInfo` / `BizAdDateInfo` | 广告频控/日期计数 |
| `pauseRewardFullLinkByStoreKitOpen` | 付费校验与广告展示联动 |

---

## 5. 网络通信（全量）

### 5.1 域名分类（90 个唯一 host，节选）

| 类别 | 域名 | 用途 |
|---|---|---|
| **业务静态页** | `jxddevapp.github.io` | `iReadNote/vipInfo.html`、`iReadNote/PrivacyPolicy.html`（GitHub Pages，静态 HTML） |
| Apple | `itunes.apple.com`、`apps.apple.com`、`ocsp.apple.com`、`crl.apple.com`、`time*.apple.com` | StoreKit / 证书校验 / 时间 |
| 广告-AdMob | `googleads.g.doubleclick.net`、`pagead2.googlesyndication.com`、`imasdk.googleapis.com`、`fundingchoicesmessages.google.com`、`admob-gmats.uc.r.appspot.com` | 广告请求/展示/合规 |
| 广告-穿山甲/火山 | `mon.snssdk.com`、`mon.toutiao.com`、`*toutiaocloud*`、`*pglstatp-toutiao.com`、`vod.volcengineapi.com`、`vod.byteplusapi.com`、`imagex.volcengineapi.com`、`neptune-api.volces.com` | 广告/素材/播放 |
| 网盘/同步 | `openapi.alipan.com`、`pan.baidu.com`、`openapi.baidu.com`、`dav.jianguoyun.com` | 阿里云盘/百度网盘/坚果云 WebDAV（书籍导入导出） |
| NTP | `ntp.aliyun.com`、`pool.ntp.org`、`time1~3.cloud.tencent.com`、`hk/tw/us.ntp.org.cn`、`time.izatcloud.net` | 时间校准（防改时间） |
| 模型/TTS | `huggingface.co`、`hf-mirror.com` | 本地 TTS 模型下载 |
| 其他 | `baike.baidu.com`、`cn.bing.com`、`swisscows.com`、`mp.weixin.qq.com` | 搜索/帮助 |

### 5.2 无自建会员 HTTP 接口的证据

1. 全量 host 扫描：不存在 `jxd.dev` 的 HTTP 主机；`jxddevapp.github.io` 仅托管两个静态 HTML。
2. `JxdCloudServerManager` 的方法全部围绕 CloudKit：`CKDatabase`、`CKRecordZone`、`CKSubscription`、`loginForce:`、`userRecordName`、`userId`，无 URL 拼接。
3. `JxdHttp`/`JxdHttpConfig` 是**通用可配置 HTTP 客户端**（自定义 header/cookie/form/动态参数），服务于书源/WebDAV/OPDS，不含硬编码会员端点。
4. CloudKit 的 zone 命名均为内容同步：`backupBookZoneID`、`backupConfigZoneID`、`backupEverBookZoneID`、`backupGroupZoneID`、`backupMarkZoneID`、`backupSourceZoneID` —— 是书籍/书签/书源同步，非会员账本。
5. 未发现 `NSUbiquitousKeyValueStore`（iCloud KVS）用法。

---

## 6. 接口清单（真实存在的会员相关通路）

> 说明：因不存在自建 HTTP 会员 API，下表按"真实通路"列出，包含协议、调用点、触发条件、鉴权与证据。
> App 侧 selector（如 `fetchProducts:completion:`）为**直接观察**；其底层调用的 StoreKit API 名称
> （如 `Product.products(for:)`）为**基于 `jwsRepresentation`/`ownershipType`/`appTransactionID`/`DeviceVerificationID`
> 等 StoreKit 2 信号的推断**，非逐指令确认。

| # | 接口/协议 | 地址/标识 | 方法 | 参数 | 鉴权 | 调用位置 | 触发条件 | 证据 |
|---|---|---|---|---|---|---|---|---|
| 1 | StoreKit 商品查询 | 系统 StoreKit（无 URL） | `Product.products(for:)` | productIDs[] | App Store 账户 | `JxdStoreKit::fetchProducts(completion:)` 0x10048c7b4；`PurchaseKit::fetchProducts:` 0x1003fd880 | 进入付费页/启动拉取 | 伪代码 + selector |
| 2 | StoreKit 购买 | 系统 StoreKit | `Product.purchase()` | productID | App Store 账户 | `JxdStoreKit::purchaseWithProductID:completion:` 0x10048dadc；`PurchaseKit::buyProduct:` 0x1003fdae0 | 用户点击购买 | 伪代码 + selector |
| 3 | 当前权益 | 系统 StoreKit | `Transaction.currentEntitlements` | — | Apple 签名 JWS | `JxdStoreKit::fetchCurEntitlements:` 0x10048e310 | 启动/复验 | 伪代码 |
| 4 | 交易历史 | 系统 StoreKit | `Transaction.all` | — | Apple 签名 JWS | `JxdStoreKit::getTransactionHistoryWithCompletion:` 0x10048e9cc | 恢复购买/校验 | 伪代码 |
| 5 | appTransactionID | 系统 StoreKit | `AppTransaction.shared` | — | Apple 签名 | `JxdStoreKit::fetchAppTransactionID:` 0x10048f3d4 | 防重放/设备绑定 | 伪代码 + 日志 |
| 6 | 设备验证 ID | 系统 StoreKit | `DeviceVerificationID` | — | 系统 | `JxdStoreKit::fetchDeviceVerificationID:` 0x10048f514 | 设备绑定 | 伪代码 |
| 7 | CloudKit 用户 | `iCloud.jxd.devapp.iReadNote` | CKQuery/Fetch | userRecordName | iCloud 账户 | `JxdCloudUser::loadFromServer`；`JxdCloudServerManager::loginForce:` | 启动/账户校验 | entitlements + selector |
| 8 | CloudKit 内容同步 | 同上 | CKModifyRecords | zoneID=backup*ZoneID | iCloud 账户 | `JxdCloudSynManager`、`JxdCloud*RecordManager` | 书籍/书签同步 | zone 字符串 + 类名 |
| 9 | NTP 时间 | `ntp.aliyun.com` 等（UDP 123） | NTPv4 | — | 无 | `JxdNtpClient::FetchWithBeginDate:...`；被 `onVerifyTrans` 调用 | 交易验证后 | 伪代码 + 类方法 |
| 10 | 激励视频发奖 | 穿山甲/AdMob SDK | SDK 回调 | `verify` 参数 | SDK 服务端 | `BuRewardAds::...ServerRewardDidSucceed:verify:` 0x1002aed38 | 广告播放完成 | 伪代码 + selector |
| 11 | 静态说明页 | `https://jxddevapp.github.io/iReadNote/vipInfo.html` | GET | — | 无 | 会员说明跳转（WebView） | 用户点击"会员说明" | cstring |

**关键鉴权结论**：会员权益无自建 token/签名体系，完全依赖 **Apple App Store 收据/JWS 签名** 与 **iCloud 账户**。App 侧无 `Authorization` header 注入会员校验请求（因为根本没有该请求）。

---

## 7. 运行时行为（未观测，明确声明）

**本轮为纯静态分析，未执行 App。** 以下属【未知】，需越狱设备/Frida/代理抓包才能坐实：
- `JxdStoreKit` 内部各 StoreKit API 的实际调用顺序与失败分支
- CloudKit 实际读写的 record type 与字段（静态只见 zone 名）
- 广告 SDK 与自身逻辑的交互时序
- 是否存在动态下发配置改变会员规则

已可确认的"运行时机制"（由代码结构推断，标【推断】）：
- 启动时 `PurchaseKit::startAccountVerify` → `JxdStoreKit` 拉权益 → `isLifeTimeValid` 遍历交易
- 交易验证后 `JxdNtpClient` 校准时间，防系统时间回拨
- 购买前 `isCanPurchase` 检测代理/VPN 与登录态，异常则拒绝
- 每 5 天（`verifySpace`）复验，超 3 台设备受限

---

## 8. 可复现步骤

```bash
# 0) 克隆流水线
git clone https://github.com/taiyuan0324/ireadnote-rea && cd ireadnote-rea

# 1) 取 IPA（Release asset 已上传，SHA256 可校验）
gh release download ireadnote-5.3.0 --pattern '*.ipa' --dir ipa
shasum -a 256 ipa/*.ipa   # 期望 6e166c07…dded5

# 2) 解包
unzip -q ipa/*.ipa -d extracted
APP=extracted/Payload/iReadNote.app

# 3) 加密校验（cryptid 必须为 0）
python3 rea/scripts/analyze_artifact.py --app "$APP" --out out --patterns rea/patterns.txt
jq '.macho.cryptid' out/summary.json

# 4) 全量网络面扫描（本报告第 5/6 节来源）
python3 rea/scripts/full_network_sweep.py "$APP" net-sweep
#   -> net-sweep/all_hosts.txt / all_urls.txt / all_paths.txt / cloudkit_tokens.txt / product_ids.txt

# 5) jxd.dev 专项
grep -rn "jxd\.dev" net-sweep/ out/cstring.txt | sort -u

# 6) Ghidra 深度反编译（需先编译 macOS 原生反编译器）
cd "$GHIDRA_INSTALL_DIR/Ghidra/Features/Decompiler/src/decompile/cpp"
make ghidra_opt ARCH_TYPE="-arch arm64" OSDIR=mac_arm_64
mkdir -p "$GHIDRA_INSTALL_DIR/Ghidra/Features/Decompiler/os/mac_arm_64"
install -m 755 ghidra_opt "$GHIDRA_INSTALL_DIR/Ghidra/Features/Decompiler/os/mac_arm_64/decompile"
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" proj ireadnote \
  -import "$APP/iReadNote" -overwrite -analysisTimeoutPerFile 900 \
  -scriptPath rea/scripts \
  -postScript ExportIREAFunctions.java out/decompiled rea/patterns-ghidra.txt

# 7) 检索会员判定函数
grep -rl "isLifeTimeValid\|verifyTrans\|isCanPurchase" out/decompiled | head
```

CI 一键：`gh workflow run ireadnote-rea.yml -f runner_label=macos-15 -f ipa_source=release ...`

---

## 9. 结果汇总

| 维度 | 结论 |
|---|---|
| 应用身份 | 爱阅记 5.3.0(277)，`jxd.devapp.iReadNote`，arm64，已解密 |
| 权限/组件 | iCloud CloudKit + APNs + App Group；1 个导入扩展；11 个火山 TTSDK 框架 |
| 代码结构 | 4759 ObjC 类 / 71080 selector / 60 section |
| 会员模型 | 买断永久 + 自动订阅 + 爱阅点软权益 |
| **jxd.dev 会员 API** | **不存在**；jxd.dev 仅为 bundle/CloudKit/AppGroup 标识 |
| 真实会员通路 | StoreKit（JWS 收据）+ CloudKit（账户/内容）+ NTP（时间防篡改） |
| 鉴权方式 | Apple App Store 收据签名 + iCloud 账户；无自建 token |
| 反作弊 | 交易遍历校验、NTP 校时、代理/VPN 探测、5 天复验、3 设备上限、环境校验 |
| 运行时 | 未观测（静态分析），已明确标注 |
| 可信度 | 基本身份/组件/网络面/函数结构=【观察】；调用时序/CloudKit 字段=【推断】；动态行为=【未知】 |

---

*本报告由静态分析产出，函数体为 Ghidra 伪代码而非原始源码。标注【推断】/【未知】处需动态验证。*
