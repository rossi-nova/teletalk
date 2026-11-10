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

## 5. 下一步（若继续）

1. 用 Ghidra 打开 `SecurityGuardSDK64.dll`，定位 `getSecurityToken` 的调用链
2. 分析 `AliStore` 的密钥来源
3. 或改走「登录代理」方案，不复刻签名

## 6. 复核

```bash
npx tsx tools/disasm/pe.ts "C:/Program Files (x86)/DingDing/main/current/MainFrame.dll"
npx tsx tools/disasm/exports.ts "C:/Program Files (x86)/DingDing/main/current/SecurityGuardSDK64.dll"
npx tsx tools/disasm/strings-in-sdk.ts "C:/Program Files (x86)/DingDing/main/current/SecurityGuardSDK64.dll"
```
