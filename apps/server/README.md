# 网关服务

钉钉 LWP 私有协议 ↔ HTTP/SSE。

## 结构

```
src/
├── config.ts              配置（环境变量）
├── index.ts               Hono 入口
├── lwp/
│   ├── frame.ts           LWP 帧编解码
│   ├── message-codec.ts   IDLSend 报文编解码
│   ├── bodies.ts          请求体构造器（逐字节验证）
│   ├── client.ts          TLS 长连接 + mid 配对
│   └── session.ts         业务语义
└── gateway/
    ├── session-manager.ts 会话持有与事件广播
    ├── mock.ts            离线回放
    └── routes.ts          REST + SSE
```

## 启动

```bash
cp apps/server/.env.example apps/server/.env   # 填入 DT_DEVICE_ID / DT_TOKEN
pnpm --filter @teletalk/server dev
```

无凭据时仍可启动，用离线回放验证。

## 接口

| 方法 | 路径 | 状态 |
|---|---|---|
| GET | `/health` | ✅ |
| GET | `/api/status` | ✅ |
| POST | `/api/connect` | ✅ |
| POST | `/api/disconnect` | ✅ |
| GET | `/api/events` | ✅ SSE |
| GET | `/api/replay?dir=` | ✅ 离线回放 |
| GET | `/api/dialogs` | ⚠️ 请求体外层未解 |
| GET | `/api/messages/:id` | ⚠️ 同上 |
| POST | `/api/send` | ✅ 构造器 10/10 验证 |

## 验证

```bash
# 离线回放（无需凭据）
curl "http://127.0.0.1:8787/api/replay?dir=.../captures/run-*/conn/*"
# → {"frames":2032,"count":12,"messages":[...]}

# 构造器自检
npx tsx scripts/test-bodies.ts
# → 2/2 通过

# 抓包解析
npx tsx scripts/test-codec.ts <抓包目录>
```

## 进度

- ✅ LWP 帧编解码（2254 帧实测）
- ✅ 消息正文编解码（短/长消息全解）
- ✅ **IDLSend 发送构造（10/10 样本字节完全一致）**
- ✅ /s/sync 推送解析（54 条真实消息）
- ✅ 字符串 ID 字段构造（2/2）
- ✅ TLS 连接、mid 配对、心跳、注册/订阅
- ✅ 离线回放、预览页
- ⚠️ 会话名与发送者昵称：profile 接口只覆盖部分用户，其余显示 uid
- ⬜ 会话列表请求体外层长度前缀
