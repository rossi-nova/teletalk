# 接线说明

本文档记录「从内存提取登录态 → 网关可用」的完整接线与踩坑。

## 1. grab-all.exe 接入启动流程

`apps/server/src/gateway/session-manager.ts` 的 `start()`：

```
isDingTalkRunning()? 否 → launchDingTalk() 自动拉起
        ↓
grabFromMemory()  每 5s 重试，直到拿到 token + did
        ↓
new DingtalkSession → connect → lookup → regInit → register(/reg)
        ↓
reg 401? → 排除旧 token 重抓，重建会话重试（最多 2 次）
        ↓
reg 200 → killDingTalk()（DT_AUTO_CLOSE 默认开）
        ↓
新会话重连 → /reg 二次验证 → sendSubscribe() → 就绪
```

**为什么关钉钉放在 /reg 之后**：token 是一次性的，如果先关钉钉再验证，发现 token 过期时已经没有源可以重抓了。

### grab-all.exe 的三个关键判据

1. **token**：优先取 LWP 请求头格式 `token:oauth_k1:`，其次退回裸 `oauth_k1:`。裸 token 大多是历史残留，会 401。
2. **did**：取 `did:<32hex>` 且**全部小写**。干扰项是 XMP 图片元数据（`xmp.iid:CD68A37A...`），全大写。
3. **x5-sign**：可选。实测业务接口不需要它，缺了也不影响。

## 2. 「必须关钉钉」约束

钉钉客户端与第三方连接**互斥**：第三方 `/reg` 成功后，服务端会立即踢掉另一个。

处理方式（`DT_AUTO_CLOSE`，默认开）：

- 抓凭据时钉钉必须在线
- `/reg` 验证通过后（token 已确认新鲜）才关闭钉钉
- 关闭后 3 秒重连，此时服务端只剩一个连接

设 `DT_AUTO_CLOSE=0` 则只打印警告，由使用者自行 `taskkill`。

## 3. 会话列表 / 消息分页

### 会话列表

`/r/Adaptor/IDLOnebox/listNewest` **不返回会话列表**（抓包里当时也是 `0xC0` 空数组），
真正的数据来自 `/r/IDLConversation/getById`（单条）。

网关做法：`listNewest` 拿 ID，拿不到就用 `SEED_CONV_IDS`（抓包中会话类请求出现过的
10 个 cid）逐个 `getById`。

### 消息分页 body（V1，已验证）

```
ab <cid>  c2  cf 0000019f  61  <cursor varint>  1d
```

| 片段 | 含义 | 备注 |
|---|---|---|
| `ab` | 字符串字段头 `0x80\|(32+11)` | cid 长度 11 |
| `c2` `cf 0000019f` | 页大小相关 | `0x19f` = 415 |
| `61` | 第 3 参数标记 | **挖掉报 `Parameter not found: 4`** |
| cursor | 游标 varint | **必须非空且为有效值**；`95482`（最新页）、`1778`（次页）|
| `1d` | 方向 | `1e` 为反向 |

### 前置条件

必须先订阅 `/s/sync`，否则返回 `400 Parameter not found: 3`。

### 响应

- 头 `zip: true`，body 是 gzip，`client.ts` 统一解压
- 内容是 Gaea 二进制，消息正文以 UTF-8 文本块散布；`message-parse.ts` 按启发式提取

### V2

`listMessagesPaginationV2` 抓包原样 body **可以 200**（早前报错是因为没先订阅）。
但响应结构与 V1 同源，同样不含 senderId，暂不使用。

### 消息字段的真相

**V1/V2 历史接口都不返回发送者**，这不是解析问题：

- 消息块以 `0a 00` `0c 00` 开头，两个字段恒为空字符串
- `MessageTail` 只是把消息头再包一层，同样没有 sender
- 能拿到的：正文（payload JSON 的 `"text"`）、`messageId`（`3-{cid}-{ts}`）、
  `sendMsgUUID`、**发送者索引**（`0x12` 后的 Gaea 数值，同一人恒定）

发送者索引是可行上限：能区分「12 个人发言」，但还原不出真实 uid。

### 消息时间

服务端不返回可读时间戳，但有两条线索：

1. **日序标记**（已实现）：每条消息块内有一对 `0xcd` 小整数，第二个值随消息变旧
   单调递减，**单位是天**。同一批抓包里从 4173 降到 4165（8 天）。
   它是相对值（没有找到绝对基准），但可以用来把消息摊到不同日期上。
2. **`sendMsgUUID` 前 4 字节**（base64 解码）：是 12 秒为单位的递增时间序，
   与日序标记严格同步，同样缺绝对基准。

因此 `createdAt` 的精度是**天**，同一天内按响应顺序（服务端按时间倒序返回）。

### 实时推送补全

`/s/sync` 推送**带完整字段**：`senderId`、`sourceNick`、`messageId`、正文。

网关做了 `messageId → {senderId, nick}` 缓存（`session.ts` 的 `rememberSenders`），
解析历史时用 `fillSenders` 回填。等有新消息进来后，同一消息的历史查询即有真实姓名。

## 4. 前端对接

`apps/preview/index.html` 是直接可用的预览页：

- 「连接钉钉」→ `POST /api/connect`
- 「刷新会话」→ `GET /api/dialogs`
- 点会话 → `GET /api/messages/:id`
- 实时推送 → `EventSource /api/events`

## 实测结果

| 指标 | 结果 |
|---|---|
| 会话 | 9 个，标题全部正确（群/单聊区分正确）|
| 消息 | 72273301682 拉回 **84 条**真实文本 |
| 全程 | 从冷启动（钉钉完全关闭）到可用约 40 秒 |
