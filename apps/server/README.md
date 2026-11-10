# 网关服务

钉钉 LWP 私有协议 ↔ HTTP/SSE，供前端消费。

## 结构

```
src/
├── config.ts              配置（环境变量）
├── index.ts               Hono 入口
├── lwp/
│   ├── frame.ts           LWP 帧编解码
│   ├── message-codec.ts   IDLSend 报文编解码
│   ├── client.ts          TLS 长连接 + 请求配对
│   └── session.ts         业务语义（注册/订阅/收发）
└── gateway/
    ├── session-manager.ts 会话持有与事件广播
    └── routes.ts          REST + SSE
```

## 启动

```bash
cp .env.example .env   # 填入 DT_DEVICE_ID / DT_TOKEN
pnpm --filter @teletalk/server dev
```

## 接口

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/health` | 存活检查 |
| GET | `/api/status` | 连接与登录状态 |
| POST | `/api/connect` | 建立到钉钉的连接 |
| POST | `/api/disconnect` | 断开 |
| GET | `/api/events` | SSE 事件流 |
| GET | `/api/dialogs` | 会话列表（待补请求体） |
| GET | `/api/messages/:id` | 历史消息（待补请求体） |
| POST | `/api/send` | 发送消息（待补请求体） |

## 当前进度

- ✅ LWP 帧编解码（用 1932 帧实测通过）
- ✅ 消息正文编解码（11 条样本中 10 条解出）
- ✅ TLS 连接、mid 配对、心跳
- ✅ 注册/订阅流程
- ⬜ 会话列表、历史消息、发送的请求体字段（protobuf 字段号未提取）
