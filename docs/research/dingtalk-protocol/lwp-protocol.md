# LWP 协议规范（抓包实证）

> 来源：2026-11-10 从本机钉钉 Windows 客户端 9.0.5-Release.261029005 抓取
> 端点：`tls-desktop.dingtalk.com:443`
> 样本：`extracted/lwp-samples/`（392 帧）

## 1. 传输层

TLS 1.3（ALPN 为空，不协商 h2）。握手完成后直接在流上跑 **LWP 文本帧**，不是 WebSocket，不是 HTTP。

## 2. 帧格式

### 请求

```
LWP <uri>\n
<header-name>:<value>\n
...
\n
[<body>]
```

### 响应

```
<code>\n
<header-name>:<value>\n
...
\n
[<body>]
```

- 头部以**连续两个 `\n`** 结束
- 若头里有 `len:<n>`，body 恰好 n 字节；无 `len` 则 body 为空
- **一帧可紧接下一帧**，同一 TCP 流上多路复用
- URI 形如 `/r/<Service>/<method>`（请求）或 `/s/<name>`（订阅）

## 3. 公共头部

| 头 | 示例 | 说明 |
|---|---|---|
| `mid` | `f0910000 0` | 消息 ID：8 位 hex + 空格 + 序号，每请求递增 |
| `did` | `bca6f4d9592a54480792269b83c457bb` | 设备 ID（32 hex） |
| `app-key` | `564ca050be89b14ee78d692f6ded748d` | 应用密钥 |
| `appkey` | `85A09F60A599F5E1867EAB915A8BB07G` | 应用标识（大写） |
| `ua` | `Win/10.0 (Windows NT;zh_CN) App/9.0.5-... Gaea/4.3.14-dingtalk.atlas4-SNAPSHOT` | 客户端标识 |
| `vhost` | `WK` | 虚拟主机 |
| `wv` | `im:3,au:3,sy:10` | 协议版本 |
| `tz` | `Asia/Shanghai` | 时区 |
| `dt` | `p` / `j` | 编码：`p`=protobuf，`j`=JSON，缺省=空 |
| `len` | `319` | body 长度 |
| `cache-header` | `app-key cs-idx-ver did tz ua vhost wv` | 声明哪些头参与缓存键 |
| `cs-idx-ver` | `0` | 配置索引版本 |
| `token` | `oauth_k1:SySip5f/...` | **登录令牌**（仅 `/reg` 携带） |
| `app-realm-orgId` | `2923369` | 组织 ID（登录后携带） |
| `via` | `tls://[ip]:443?isp=telecom&rm=na620...` | 当前路由 |

## 4. 连接生命周期

```
1. /r/Aladdin/lookup          → 服务发现，返回 domainList + ipList
2. /reg/init                  → 长连接初始化
3. QrcodeI/generateForConfirmLogin  → 取二维码
   QrcodeI/pushConfirmLogin         → 推送扫码确认
   LoginI/loginByFido               → 换取 token（需 x5-sign 签名）
4. EnterpriseI/getRealmModels       → 取组织列表
   EnterpriseI/injectRealmLWPHeaders→ 注入 orgId
5. /reg                             → 用 token 注册长连接 ★
6. /s/sync  /s/synca  /s/feynman    → 订阅消息推送
7. 之后业务请求（带 orgId）
```

## 5. 鉴权链

- **`/reg` 携带 `token: oauth_k1:<base64>`** —— 这是真正的登录凭据，独立于 Cookie
- `LoginI/loginByFido` 需要 `x5-sign` / `x5-miniwua` / `x5-umid-token` 三个签名头，由 `SecurityGuardSDK64.dll` 生成
- 登录成功后所有请求带 `app-realm-orgId`

## 6. 关键接口

| URI | 用途 |
|---|---|
| `/r/Aladdin/lookup` | 服务发现（返回服务器 IP 列表） |
| `/reg` `/reg/init` | 长连接注册与初始化 |
| `/r/Sync/getState` `/r/Sync/ackDiff` | 增量同步 |
| `/s/sync` `/s/synca` `/s/feynman` `/s/para` | 推送订阅 |
| `/r/IDLMessageStatus/updateToReadV2` | 已读回执 |
| `/r/IDLMessageStatus/updateToViewV2` | 已读上报 |
| `/r/Adaptor/ChatContextI/getChatContextByTypes` | 会话上下文 |
| `/r/Adaptor/ContactI/getUserEmployeeInfos` | 员工信息 |
| `/r/Adaptor/TextEmotionI/listCustomTextEmotion` | 自定义表情 |
| `/r/Adaptor/TangleNetworkSession/heartbeat` | 心跳（tangle 子系统） |
| `/r/LogI/batchLog` | 日志上报 |

## 7. Body 编码（实证）

### 已确认

| dt | 编码 | 证据 |
|---|---|---|
| `j` | 明文 JSON | 首字节 `0x5b` = `[`，如 `[{"sectionType":1000,...}]` |
| `p` | protobuf 变体 | tag 为 varint，字段真实存在 |
| 缺省 | 同 `p` | `/r/Aladdin/lookup` |

### tag 解析（已实证）

```
da 00   → varint = 0x5a = 90 → field 11, wire type 2
```

即**两字节 varint 表示 tag**，符合 protobuf 规范。

### 长度字段：已破解（实证）

用 4 条内容递增的消息做差分，规律完全线性：

| 正文 | 正文字节数 | 总长 | 正文前的 marker |
|---|---|---|---|
| `测试` | 6 | 240 | `0xa6` |
| `测试长度` | 12 | 246 | `0xac` |
| `测试长度长度` | 18 | 252 | `0xb2` |
| `测试长度长度长度` | 24 | 258 | `0xb8` |

**marker − 正文字节数 恒为 0xA0（160）。**

```
marker = 0xA0 + len            (len ≤ 95)
```

即结构为：

```
02 81 01 <0xA0+len> <正文 UTF-8> 07 90 06 01 07 ...
```

- `0xA0` 可解读为 protobuf tag：field 20 / wire 0
- 长度直接加在 tag 上，省去独立的长度字节
- 超过 95 字节时应切换为变长编码（**未验证**，需要更长的消息样本）

> 注意：`0x81 0x01` = varint 129 已验证可复现，说明**同一种长度编码**在别处用到了 varint 形式。
### 编解码器

`tools/mitm/idl-codec.mjs` 已实现并验证，可从抓包文件直接提取：

```bash
node tools/mitm/idl-codec.mjs captures/run-*/conn/*/0067-c2s.bin
```

输出：
```json
{
  "mid": "f09102f3 0",
  "text": "测试",
  "cidHint": "VaXHx2W@",
  "senderHint": "79553200501",
  "orgId": "880519069",
  "convNameHint": "帕鲁(班主任)"
}
```

### 实例：发送一条文本消息

```
LWP /r/IDLSend/send
mid:f09102f3 0
dt:p
len:240
```

body 内可直接读出的内容（按字节偏移）：

| 偏移 | 内容 | 推断 |
|---|---|---|
| 3 | `VaXHx2W@` | 会话 cid 片段 |
| 13 | `79553200501` | 发送者 uid |
| 33 | `测试` | **消息正文** |
| 49 | `customUnreadCountType` | 扩展字段键 |
| 71 | `edu_guardian` | 扩展字段值 |
| 84 | `customUnreadTotalCount` | 扩展字段键 |
| 109 | `oid` → `880519069` | 组织 ID |
| 117 | `钉钉帕鲁(班主任)` | 会话名 |
| 157 | `{"empVer":0,"orgId":"880519069"}` | **明文 JSON** |
| 193 | `@lQLP...VAA` | 资源/图片 ID |

> 这条请求说明：**文本消息的正文在 body 里是未加密的 UTF-8**，可以直接提取。

## 8. 服务发现响应

`/r/Aladdin/lookup` 的响应 body（`dt:p` 但内含 JSON 片段）：
```json
{"domainList":[{"expire":21600,
  "ipList":["http://123.180.156.66:443?rm=na620&static=1&isp=telecom",
            "http://123.180.156.137:443?rm=na610&static=1&..."]}]}
```

## 9. 未解决

1. **protobuf 字段号**：body 是 protobuf，但 schema 的 tag 编号未提取（需反汇编 `MainFrame.dll` 或运行时 dump）
2. **`x5-sign` 生成算法**：在 `SecurityGuardSDK64.dll` 中
3. **`token` 的有效期与刷新**：需长时间观察

## 复现

```bash
node tools/mitm/parse-lwp.mjs captures/run-*/conn/*/ > parsed.txt
```
