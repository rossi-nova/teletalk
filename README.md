# teletalk

**用 Telegram 风格的前端，接钉钉的私有协议。**

> 状态：协议研究完成，网关可运行，扫码登录未闭环。
> 详见 [`docs/research/dingtalk-protocol/STATUS.md`](docs/research/dingtalk-protocol/STATUS.md)

## 这是什么

- **前端**：极简预览页（`apps/preview`），后续可换 React/Telegram 风格 UI
- **网关**：`apps/server`，把钉钉 LWP 私有协议转成 HTTP + SSE
- **协议研究**：`docs/research/dingtalk-protocol/`，从零逆向出的完整协议文档

## 已经搞清楚的

| 项 | 状态 |
|---|---|
| 客户端形态 | Qt5 + C++ 原生（非 Electron）|
| 传输层 | TLS 1.3 + 自定义文本帧（LWP）|
| 协议帧格式 | 完全破解 |
| 消息编解码 | 字节级验证 10/10 |
| RPC 路由 | 1193 条 |
| 真连钉钉 | ✅ 成功 |

## 还卡着的

| 项 | 原因 |
|---|---|
| 发送消息 | 会话 ID 不在请求体里，需进一步逆向 |
| 扫码登录 | 需 `x5-sign` 签名（阿里安全 SDK）|
| 长期可用 | Token 数小时失效 |

## 快速开始

```bash
pnpm install

# 1. 抓取登录态（需先配置 Clash 规则，见 tools/mitm/clash/README.md）
tools\capture-login.bat

# 2. 启动网关
pnpm --filter @teletalk/server dev

# 3. 浏览器打开
# http://127.0.0.1:8787/
```

## 目录

```
apps/
  server/            网关（Hono + LWP 协议层）
  preview/           预览页（单文件 HTML）
docs/research/
  dingtalk-protocol/ 协议文档（从这里开始看）
packages/shared/     共享类型
tools/
  mitm/              MITM 抓包环境 + Clash 规则
  disasm/            PE 分析工具
  extract-token.ts   登录态提取
scripts/             测试与验证
```

## 文档导航

| 想知道 | 看 |
|---|---|
| 项目整体状态 | `docs/research/dingtalk-protocol/STATUS.md` |
| LWP 协议怎么工作 | `docs/research/dingtalk-protocol/lwp-protocol.md` |
| 客户端长什么样 | `docs/research/dingtalk-protocol/windows-client.md` |
| 扫码登录怎么做 | `docs/research/dingtalk-protocol/qrcode-login.md` |
| 反汇编发现 | `docs/research/dingtalk-protocol/reverse-notes.md` |
| 有哪些接口 | `docs/research/dingtalk-protocol/extracted/routes.md` |

## 许可

自研部分 GPL-3.0。若将来接入 telegram-tt，需同时遵守其 GPL-3.0。
