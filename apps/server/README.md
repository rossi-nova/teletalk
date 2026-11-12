# teletalk 网关

把钉钉私有协议（LWP）包装成 REST + SSE，供前端调用。

## 使用

```bash
pnpm --filter @teletalk/server dev
```

打开 <http://127.0.0.1:8787>（内置预览页）。

首次点「连接钉钉」时网关会：

1. 若钉钉未运行则**自动拉起**（需此前已扫码登录过一次，会自动登录）
2. 从钉钉进程内存抓取 `token` / `did`（grab-all.exe）
3. 用 token 走 `/reg` 验证
4. **验证通过后才关闭钉钉**（避免多客户端互踢），再用已验证的凭据重连
5. 订阅 `/s/sync` 等推送通道

全程约 30~40 秒，之后连接稳定。

## 接口

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/status` | 连接状态 |
| POST | `/api/connect` | 启动会话（自动抓凭据） |
| POST | `/api/disconnect` | 断开 |
| GET | `/api/dialogs` | 会话列表（`?ids=a,b` 指定）|
| GET | `/api/dialogs/:id` | 单个会话 |
| GET | `/api/messages/:dialogId?limit=30` | 历史消息 |
| POST | `/api/send` | 发送文本（待完善）|
| GET | `/api/events` | SSE 实时推送 |

## 已知约束

- **token 极短命**：钉钉每次重启都会轮换 token，且复用后立即失效。所以必须「拉起钉钉 → 立即抓 → 立即连」。
- **必须订阅**：`listMessagesPagination` 要求先 `/s/sync` 订阅且等待约 2 秒，否则报 `Parameter not found`。
- **游标固定**：服务端校验具体游标值，任意值会被拒绝。当前默认 `95482`（抓包最新页），向前翻页需 `1778`。
- **消息字段不完整**：V1 响应是 Gaea 二进制，sender/时间戳字段号未破解，目前只提取文本块。
- **x5-sign 非必需**：实测不带签名反而更稳，业务请求已全部走无签名头。
