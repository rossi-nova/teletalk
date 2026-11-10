# teletalk

Telegram Web 前端 + 钉钉私有协议的 IM 客户端。

- **前端**：fork `Ajaxy/telegram-tt`（Telegram Web A），把 MTProto 数据层换成自研 REST/SSE 适配器。
- **网关**：Hono + Node 26，负责登录态、消息同步、媒体中转。
- **钉钉侧**：代理手机客户端，走私有协议，不依赖开放平台。

## 当前阶段

**阶段 0：协议攻关**。工程骨架、探针脚本与研究目录已就位，等待抓包样本。

## 前提与事实

- 钉钉网页版 `im.dingtalk.com` 已下线（系统维护页），Web 代理路线不可行。
- 钉钉 Linux 官方客户端仍在维护（`9.0.0.261105002`，2026-11），可用于对照设备字段。
- 协议蓝本是**手机 App 抓包**，样本脱敏后放 `docs/research/fixtures/`。

## 目录

```
docs/research/dingtalk-protocol/   协议事实表与判定
docs/research/fixtures/            脱敏后的抓包样本
scripts/probe.ts                   样本重放探针（阶段 0 验收工具）
apps/ packages/ src/               网关与前端（阶段 1 起填充）
```

## 使用

```bash
pnpm install
cp docs/research/fixtures/README.md  #（看格式说明）
pnpm probe docs/research/fixtures/M1.json
```

环境变量（本地 `.env`，不进版本库）：

| 变量 | 说明 |
|------|------|
| `DT_COOKIE` | 登录态 cookie 串 |
| `DT_TOKEN` | 主要 token |
| `DT_DEVICE_ID` | 设备标识 |

## 许可

前端沿用上游 GPL-3.0；本仓库自研部分同 GPL-3.0（见 `docs/DECISIONS.md`）。
