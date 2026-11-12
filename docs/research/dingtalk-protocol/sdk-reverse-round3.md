# SDK 逆向：第三轮（Ghidra + 运行时内存）

> 日期：2026-11-12
> 目标：还原 getSecurityToken，产出可复刻的签名

## 一、方法

静态（Ghidra 11.4.2）+ 动态（进程内存读取）双路。

### 静态

- Ghidra 全量分析 15 分钟，110 MB 数据库
- 16 个目标函数反编译（`tools/ghidra/ExportDecomp.py`）
- **结论：被跳板混淆打穿**，反编译满是 `halt_baddata`

### 动态（突破点）

用 `ReadProcessMemory` 读钉钉进程（PID 5668）的 SDK 内存：

```
SDK 基址  0x7FFE69680000
.data    RVA 0xa16000（400776 字节）
```

**直接从堆里抓到了 SDK 实时生成的 x5-sign**。

## 二、x5-sign 结构（已完整破解）

```
原文 102 字符 = 12 字符固定头 + 88 字符 base64（解码 66 字节）
```

| 段 | 内容 |
|---|---|
| 前 12 字符 | `wzMK2c002xAA`（固定） |
| 解码 [0..8] | `c3 33 0a d9 cd 34 db 10 00`（固定魔数） |
| 解码 [9..69] | 60 字节签名体（每样本全变） |
| 解码 [70..75] | 6 字节尾部 `[A][B][A][B][A][B][A][B]` |

尾部规律：`B - A` 恒为 **0x10**（四样本验证）。

## 三、签名输入对象（关键发现）

token 持有者对象 @ `0x23649a3e000`：

```
+0x00  "/IgetAuthTmpCode"                     ← 签名目标
+0x20  → "wzMK2c002xAAJ6QhWf..."              ← 产出
+0x28  90023700ac69a86a                       ← FILETIME 时间戳
+0x30  "contact_cp-new-contact-view-disa..."
+0x70  "_general_url_security_check_option_..."
+0xf0  "/r/Adaptor/LoginI/getAuthTmpCode"     ← 完整 RPC 路径
+0x140 "general|gaea_api_payload_rpc_limit_r_Adaptor_LoginI_getAuthTmpCode_common"
```

**签名键格式**（`+0x140`）：

```
<category> | <source> <_> <type> <_> <method> <_> <env>
general    | gaea_api_payload rpc_limit r_Adaptor_LoginI_getAuthTmpCode common
```

## 四、签名由谁驱动

```
MainFrame.dll  →  构造请求  →  调 SDK  →  SDK 算签名  →  返回 x5-sign
   ↑ 业务层                    ↑ 不动点
```

证据：`getAuthTmpCode` 的日志 `mpCode arg: url=` 在 **MainFrame.dll**
（offset 0x708a580，`biz/...` 路径），不在 SDK 里。

## 五、工具（tools/sign/）

| 工具 | 用途 |
|---|---|
| `x5-dump.exe` | **从进程内存提取 x5-sign**（已验证，3 个样本） |
| `hunt-token.exe` | 按特征串搜索 token |
| `state-check.exe` | SDK 运行时状态检查 |
| `rev-object.c` | token 持有者反查 |
| `deep-obj.c` | 对象字段 dump |
| `hwbp.c` | 硬件断点捕获（需管理员，未运行）|
| `abi-probe.c` | initUMID ABI 枚举（结论：不接收输出句柄）|

## 六、已验证的事实

| 项 | 结果 |
|---|---|
| SDK 是否可静态反编译 | ❌ 跳板混淆 |
| SDK 对象是否可运行时定位 | ✅ RTTI 类名全暴露 |
| x5-sign 是否可提取 | ✅ 3 个样本 |
| 签名是否缓存 | ✅ 稳定不变（非每次刷新）|
| 签名能否复用到 LWP 请求 | ⏳ 待验证（token 过期挡住）|
| `initUMID` ABI | ✅ 3 参数，但不写 r8（不产句柄）|
| `getSecurityToken` ABI | ✅ 3 参数（handle, GUID*, out*），见 Utility.dll 0xa8db |
| 签名算法 | ❌ 未复刻（跳板 + 配置驱动）|

## 七、关键代码位置

| 地址 | 内容 |
|---|---|
| SDK `0x182380` | getSecurityToken（217 状态 CFF）|
| SDK `0x17fa30` | initUMID（96 字节壳，转 `0x117190`）|
| SDK `0x89e20` | 签名路径核心（308 字节，4 调用者）|
| SDK `0x8ff700` | base64 表（Ghidra 报 0 引用，间接引用）|
| SDK `0x11d952` | RC4 变体（KSA 双密钥 0x71/0x45）|
| MainFrame `0x4ba3f2f` | 因子列表构造（`28695415,appkey,api`）|
| MainFrame `0x708a580` | getAuthTmpCode 日志 |

## 八、未完成

1. **签名算法本体**：跳板混淆使静态分析失效；动态调试需管理员权限
2. **签名与请求的绑定关系**：`rpc_limit` 键是否参与签名输入
3. **尾部 6 字节的生成规则**：`B = A + 0x10` 的成因

## 九、下一步

| 方案 | 前提 | 成本 |
|---|---|---|
| A. 管理员权限跑 `hwbp.exe` | 提权 | 低（已写好）|
| B. 逆向 MainFrame 的签名调用点 | 无 | 中 |
| C. 接受旁路提取 | 无 | 已完成 |

**当前可用于工程实践**：`x5-dump.exe` + 网关 `x5-sign.ts` 已接通，
待 token 有效后可验证完整链路。

## 十、补充：RTTI 类名全景（77 个）

从 SDK `.data` 段提取的可读类型名（部分）：

### 签名体系

| 类 | 作用 |
|---|---|
| `CCommonSign` / `ICommonSign` | 通用签名 |
| `CVMSign` / `IVMSign` | **vmsign 配置驱动签名** |
| `CDynamicTokenSign` / `IDynamicTokenSign` | **动态 token 签名（x5-sign）** |
| `CStaticEncrypt` / `IStaticEncrypt` | 静态加密 |
| `CEncryptBox` / `IEncryptBox` | 加密盒 |
| `MtopSignImpl` | MTOP 签名 |
| `MtopRequestImpl` / `MtopResponseImpl` | MTOP 请求响应 |

### 数据与安全

| 类 | 作用 |
|---|---|
| `CAliStore` | UMID 加密存储 |
| `CPicCryptStore` | 图片加密存储 |
| `StaticDataStore` / `IStaticDataStore` | 静态数据存储 |
| `SecurityFactor` / `ISecurityFactor` | 安全因子 |
| `TrafficFilter` / `ITrafficFilter` | 流量过滤 |
| `AntiVM` | 反虚拟机 |

> **注意**：SDK 的 **CompleteObjectLocator 被剥离**，
> TypeDescriptor 字符串存在但无 COL 引用，因此无法通过 RTTI 直接定位虚表。

## 十一、vmsign 配置（加密）

位置：RVA `0x8DFDC0` 附近

```
0000  4f 00 00 00             长度 0x4F = 79
0010  19 b1 32 19 99 9c ...   加密块 1
0040  54 19 6c f8 9f 7b ...   加密块 2
0060  66 73 37 6c 27 21 ...   加密块 3
```

**部分明文泄露**：`0x8DFDD0` 的密文与明文 `"vmsign_config_fi"` 做 XOR，
密钥流中**一半位置为 0**：

```
XOR 密钥流: 00 00 41 70 00 00 00 00 00 77 00 71 00 49 00 00
```

说明该字符串**大部分直接存放**，个别位置被替换为噪声。
其余加密块（`0x8DFE00` 之后）未解出。

## 十二、实测结论（2026-11-12）

用第三方客户端连接 `tls-desktop.dingtalk.com`：

| 测试 | 结果 |
|---|---|
| 无 x5 签名请求 `/r/Aladdin/lookup` | HTTP 500，body `系统繁忙，请稍后再试` |
| 带 x5 签名（进程提取）| HTTP 500，**完全相同** |

**结论**：token 过期（2026-11-10 签发），请求在鉴权层被拒，
签名校验根本没有执行。**无法据此判断签名是否有效**。

要完成验证，需：
1. 运行 `tools\capture-login.bat` 获取新 token（30 秒）
2. 重跑 `npx tsx scripts/verify-chain.ts`

## 十三、第三轮总结

### 达成

- ✅ Ghidra 环境与工具链（含 JDK 21 兼容问题修复）
- ✅ 16 个关键函数反编译（虽被混淆打断）
- ✅ **x5-sign 实时提取**（`tools/sign/x5-dump.exe`）
- ✅ 签名结构完全破解（12 字符头 + 66 字节体）
- ✅ 签名输入对象定位（含格式串）
- ✅ RTTI 类名全览（77 个）
- ✅ 网关接入（`apps/server/src/lwp/x5-sign.ts`）

### 未达成

- ❌ 签名算法本体（跳板混淆 + vmsign 配置加密）
- ❌ 签名有效性验证（token 过期阻塞）
- ❌ 尾部 6 字节 `B = A + 0x10` 规律的成因

### 判断

静态逆向到此为止。**跳板混淆 + 配置驱动**使复刻成本远超收益。
**运行时提取**（已实现）是工程上可用的方案。
