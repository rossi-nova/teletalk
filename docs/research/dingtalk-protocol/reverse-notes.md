# 反汇编分析记录

> 对象：`MainFrame.dll`（171,636,584 字节，PE32+，ImageBase 0x180000000）
> 工具：自研 PE 解析器 + 字符串交叉引用（`tools/disasm/`）

## 1. PE 结构

| 节 | 虚拟地址 | 大小 | 说明 |
|---|---|---|---|
| `.text` | 0x1000 | 113 MB | 代码，**未 strip 符号**（含 RTTI 与函数名） |
| `.rdata` | 0x6cc5000 | 43 MB | 只读数据、字符串 |
| `.data` | 0x95e4000 | 7.9 MB | 可写数据 |
| `.pdata` | 0x9d7a000 | 3.4 MB | 异常表 |
| **`.detourc`** | 0xa0b0000 | 8.6 KB | **Microsoft Detours 代码段** |
| **`.detourd`** | 0xa0b3000 | 24 B | Detours 数据段 |
| `.rsrc` | 0xa0b4000 | 2.4 MB | 资源 |
| `.reloc` | 0xa2fd000 | 1.06 MB | 重定位 |

**发现**：存在 `.detourc` / `.detourd`，说明程序内置 Detours 做运行时函数挂钩（反调试/监控）。

## 2. 消息字段结构（从 .rdata 的 JSON 定义提取）

```json
{
  "uuid": "Uf7bNJj",
  "conversationId": "65440722019",          // ★ 11 位纯数字
  "messageId": 22089984436203,
  "sendProgress": -1.0,
  "openId": 751900669,
  "contentType": 1,
  "textContent": { "text": "..." },
  "contentVersion": "0",
  "createdAt": "1738900140348",
  "creatorType": 1,
  "extension": {
    "oid": "21001",
    "openConversationId": "cidkTrV1NjI7a7ew/Een6ePbQ==",
    "realmFlag": "1",
    "realmOrgid": "439446171",
    "sendMsgUUID": "Uc5Pp9w@",              // ★ 7 字符，含 @
    "topicId": "21791327490369"
  }
}
```

### 关键确认

**`sendMsgUUID` 就是 `IDLSend/send` body 里的 `aX?????@` 字段。**

证据：`.rdata` 中的 JSON 实例 `"sendMsgUUID": "Uc5Pp9w@"`，格式与抓包完全一致（`aX` + 4 字符 + `@`）。

## 3. 会话 ID 未解之谜

对同一 uid 的 10 条 `IDLSend/send` 做逐字节差分：

```
偏移 0-6     恒定
偏移 6-10    变动 4 字节 ← sendMsgUUID 的中段
偏移 10-35   恒定
偏移 35+     正文（长度不同导致整体错位）
```

body 内仅有的数字串：

| 偏移 | 值 | 含义 |
|---|---|---|
| 13 | `79553200501` | 发送者 uid |
| 113 | `880519069` | orgId |
| 178 | `880519069` | orgId（JSON 副本） |

**没有 11 位的 `conversationId`。**

### 推论

`IDLSend/send` 的会话归属**不在请求体内**，可能由以下之一决定：

1. 长连接上下文（`/reg` 时注册的会话集合）
2. 隐藏在 body 的定长二进制字段中（如偏移 10-35 的某段）
3. 由 `sendMsgUUID` 关联服务端的临时会话映射

## 4. 未完成

- 未定位 `IDLSend` 的编码函数（`.text` 段 113MB，直接 LEA 搜索未命中）
- 未确认会话上下文的传递方式
- token 有效期短（抓包后数小时即 401），长期方案需实现扫码登录

## 5. 复现

```bash
npx tsx tools/disasm/pe.ts <MainFrame.dll>              # 节表
npx tsx tools/disasm/xref.ts <dll> <字符串> --limit 5    # 交叉引用
```
