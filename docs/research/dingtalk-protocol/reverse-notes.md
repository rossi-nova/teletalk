# 逆向分析记录

> 对象：钉钉 Windows 客户端 9.0.5-Release.261029005
> 分析日期：2026-11-10
> 状态：**暂告段落**

## 1. 客户端组成

| 文件 | 大小 | 说明 |
|---|---|---|
| `MainFrame.dll` | 171 MB | 主程序，Qt5 + C++ 原生 |
| `libgaea.dll` | 8.6 MB | 长连接框架 LWP |
| `SecurityGuardSDK64.dll` | 11 MB | 阿里安全 SDK（签名） |
| `security.dll` | 113 KB | 安全 SDK 的薄封装（3 个导出）|
| `web_content.dat` | 102 MB | Web 资源，ZipCrypto 加密 |

### PE 节表（MainFrame.dll）

| 节 | 虚拟大小 | 说明 |
|---|---|---|
| `.text` | 113 MB | 代码，保留 RTTI 与符号 |
| `.rdata` | 43 MB | 字符串与结构定义 |
| **`.detourc`** | 8.6 KB | **Microsoft Detours 代码** |
| **`.detourd`** | 24 B | **Detours 数据** |

> `.detourc` / `.detourd` 说明程序内置运行时函数挂钩，用于监控与反调试。

## 2. SecurityGuardSDK64.dll

### 导出函数（6 个）

| 函数 | 作用 |
|---|---|
| `initUMID` | 初始化 UMID 令牌 |
| `getSecurityToken` | **生成签名令牌** |
| `getCompatibelDcpToken` | 兼容版 DCP 令牌 |
| `freeSecurityToken` | 释放令牌 |
| `zeroUMID` | 清空 UMID |
| `QueryInterface` | 接口查询 |

`getSecurityToken` 位于 RVA `0x182380`。

### 保护情况

**未加壳**：无 VMProtect / Themida / OLLVM 特征，原生 AMD64 编译。

### 内部线索

| 字符串 | 含义 |
|---|---|
| `x-sign:` | `x5-sign` 的信号标记 |
| `..\SignBox\SignBR` | 签名模块 |
| `vmsign_config_fi` | **签名由配置驱动**（服务端可下发新版）|
| `AliStore` | UMID 的加密存储层 |
| `SHA256/SHA512/AES/X25519 ... CRYPTOGAMS` | 内嵌 OpenSSL |

### 结论

逆向 `getSecurityToken` 需要：
1. 反汇编 9.2 MB 的 `.text`
2. 理解 `AliStore` 的加密与密钥来源
3. 复刻 `vmsign` 配置驱动的算法

**且**：签名算法配置化，服务端可随时改版；主程序有 Detours 监控。

**评估：投入产出比差，暂不推进。**

## 3. 消息结构（从 .rdata 提取）

```json
{
  "uuid": "Uf7bNJj",
  "conversationId": "65440722019",
  "messageId": 22089984436203,
  "contentType": 1,
  "textContent": { "text": "..." },
  "extension": {
    "oid": "21001",
    "openConversationId": "cidkTrV1NjI7a7ew/Een6ePbQ==",
    "realmOrgid": "439446171",
    "sendMsgUUID": "Uc5Pp9w@",
    "topicId": "21791327490369"
  }
}
```

### 关键结论

**`sendMsgUUID` = `IDLSend/send` body 中的 `aX?????@` 字段**（消息 UUID，非会话 ID）。

### 未解：会话 ID 的位置

对同 uid 的 10 条发送做逐字节差分：

```
偏移 0-6     恒定
偏移 6-10    变动 ← sendMsgUUID
偏移 10-35   恒定
偏移 35+     正文（长度差异导致错位）
```

body 内数字串仅有：发送者 uid（偏移 13）、orgId（偏移 113/178）。**不含 11 位的 conversationId。**

推论：会话归属可能由长连接上下文（`/reg` 注册关系）决定，未证实。

## 4. 工具

见 `tools/disasm/`：PE 解析、交叉引用、导出表、极简反汇编、字符串分类。

**局限**：这是探查级工具，深度逆向需要 Ghidra / IDA Pro。

## 4bis. 第二轮逆向（2026-11-12）

### 4bis.1 调用宿主：不是 security.dll

| DLL | 真实职责 |
|---|---|
| `security.dll` | **误导**：文件上传安全校验（`/r/Adaptor/MoziConfBusinessSecurityI/validate`）|
| `Utility.dll` | **真正的加载器**：`ali_umid_util.cpp`，`LoadUmidSdk → initUMID → 等事件 → getSecurityToken` |
| `MainFrame.dll` | **签名注入方**：`baxia_manager_helper.cc`（`biz/security/security2`），阿里 Baxia 组件 |

`Utility.dll` 的日志串已完整暴露调用时序（`[base_login] GetUmidToken …`）。

### 4bis.2 SDK 接口形态：QueryInterface 工厂

MainFrame 通过 `LoadLibraryA("SecurityGuardSDK64.dll")` + `GetProcAddress("QueryInterface")` 取出 SDK 入口，
路径由 `GetModuleFileNameA → PathRemoveFileSpecA → PathAppendA` 拼出。

`QueryInterface(id, void** out)` 的 switch 混淆表（RVA `0xf9134`，11 项）：

| id | 接口 | 实现 |
|---|---|---|
| `0x128` | ISecurityFactor | 返回 `.data` 全局单例 `0xa29710` |
| `0x12a` | ITrafficFilter | `new(184B)` + 构造 `0x168e60`，登记到全局链表 |
| 其余 9 项 | 其它因子接口 | — |

两个接口构造后各自调 `vtbl[0]()` 启动：

- ITrafficFilter 虚表 @ **RVA `0x8e1438`**，8 个槽（`0x169000` / `0x16a850` / `0x16b0d0` / `0x16ce90` / `0x16d3a0` / `0x16d6e0` / `0x16fb00` / `0x176a10`）

### 4bis.3 混淆跳板（重要）

SDK 的**所有**函数入口都套一层「常量算术 + jmp / push-ret / call-pop」跳板，
跳板输入全部是编译期常量（唯一运行时量是 `mov dword [rbp-8], imm; movsx r, word [rbp-8]`）。

已实现自动符号执行器 `tools/disasm/follow.ts`：
`--scan`（线性定位首个槽写）+ `--chain`（连续穿透多层跳板）。

### 4bis.4 签名头清单

SDK 内联构造，规避字符串扫描：

| 头 | 生成处 |
|---|---|
| `x-utdid:` | `0x11bce1`（值经 URL 编码器 `0x11bd40`）|
| `x-devid:` | `0x11be32` |
| `x-sign:` | `0x11d850` |
| `x-extdate:` | `0x11dceb`（`mov rax, 7461647478652D78h` 立即数拼接）|

MVP 抓包中的对应头：`x5-sign` / `x5-miniwua` / `x5-umid-token` / `x5-sgext` / `x5-bx-version`。

### 4bis.5 已破解的加密层：RC4 变体

RVA `0x11d952`–`0x11db58`：

```
S[i] = i                                  // 0x8DE540 起 256 字节
KSA（步长 2 展开，密钥字节 0x71 / 0x45 交替）：
  for (i = 0; i < 256; i += 2) {
     d = S[i];   j = (j + d + 0x71) & 0xff;  swap(S[i], S[j]);
     c = S[i+1]; k = (j + c + 0x45) & 0xff;  swap(S[i+1], S[k]);
  }
PRGA：标准，输出 11 字节
明文源：0x8DFB25（11 字节）  输出：0xA29F85（全局缓存）
```

离线复算脚本：`scripts/rc4-variant.ts`。解出 `c30c9e4e5d92683e2e6464`（二进制混淆常量，非字符串），
说明这是**内层熵源**，签名主体仍在其上层。

另有第二处 RC4（RVA `0x152c60`，key `"Uay"`，3 字节输出）——属于另一条因子路径，与上面独立。

### 4bis.6 新工具

| 文件 | 用途 |
|---|---|
| `dis64.ts` | iced-x86 反汇编：`listing` / `imports` / `exports` / `xref-iat` / `xref-rva` / `iat` |
| `follow.ts` | 跳板自动穿透（`--scan --chain`）|
| `dump-vtables.ts` | 虚表槽位 dump |
| `find-str.ts` / `peek.ts` | 字符串定位与任意 RVA 查看 |
| `scan-vtcall.ts` | 区域内虚表间接调用扫描 |

### 4bis.7 结论

- 签名是**分层**的：RC4 变体只是最内层熵源，外层还有很多（`vmsign_config_fi` 配置驱动的部分尚未触及）
- 若目标是跑通登录，**旁路提取仍是最优**——复刻签名需要每层都逆，且配置可由服务端改版
- 但**协议层已完全打通**：只要拿到 token + x5 头，网关即可真连

## 5. 下一步（若继续）

1. 追 `getSecurityToken`（RVA `0x182380`）→ 它是 `X-Sign` 对外入口，虚表方法最终会落到它
2. 分析 `AliStore` 的密钥来源（UMID 落盘加密）
3. 或改走「登录代理」方案，不复刻签名

## 6. 复核

```bash
# 旧（main/current 是旧版本目录）
npx tsx tools/disasm/pe.ts "C:/Program Files (x86)/DingDing/main/current/MainFrame.dll"

# 新（9.0.5-Release.261029005 实际安装位置）
SDK="C:/Program Files (x86)/DingDing/main/current_new/SecurityGuardSDK64.dll"
npx tsx tools/disasm/dis64.ts exports "$SDK"
npx tsx tools/disasm/dis64.ts listing "$SDK" 182380 80
npx tsx tools/disasm/follow.ts "$SDK" 169000 --scan --chain
npx tsx scripts/rc4-variant.ts
```
