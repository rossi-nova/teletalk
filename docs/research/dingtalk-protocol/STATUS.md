# teletalk 项目状态

> 停更日期：2026-11-10
> 阶段：协议研究完成，网关可用，扫码登录未闭环

## 一、项目目标

用 Telegram Web 前端 + 钉钉私有协议，做一个 IM 客户端。

**实际路线调整**：前端方案从「深改 telegram-tt」改为「先做极简预览页验证数据」，
因为 telegram-tt 是完整 Telegram 客户端（自研 Teact 框架、30 个协议文件），
深改成本远超预期。

## 二、已完成

### 协议研究（核心成果）

| 文档 | 内容 |
|---|---|
| `windows-client.md` | 客户端形态、网络架构、接口清单 |
| `lwp-protocol.md` | **LWP 协议规范**（帧格式、字段、生命周期）|
| `qrcode-login.md` | 扫码登录协议与障碍 |
| `reverse-notes.md` | 反汇编分析（PE、SDK、消息结构）|
| `extracted/routes.md` | 1193 条 RPC 路由 |
| `extracted/live-protocol.proto` | 4 个内嵌 protobuf 定义 |

### LWP 协议（已完整破解）

```
请求  LWP <uri>\n<k:v>\n...\n\n<body>
响应  <code>\n<k:v>\n...\n\n<body>
```

- 传输：TLS 1.3 + 自定义文本帧（非 WebSocket、非 HTTP）
- 心跳：42 秒
- 鉴权：`/reg` 的 `token: oauth_k1:...` + `did` 设备标识

### 消息编解码（已验证）

| 项 | 状态 |
|---|---|
| 短消息 token（≤95B） | `marker = 0xA0 + len`，1 字节 |
| 长消息 token（>95B） | `marker = 0xDA + 高位 + 低8位`，3 字节 |
| 发送构造 | **10/10 样本字节完全一致** |
| 正文提取 | 靠尾部固定串 `07 90 06 01 07` 定位 |
| 推送解析 | `/s/sync` 提取 senderId/convId/text/nick |

### 网关（可运行）

```
apps/server/
├── src/lwp/         协议层（帧、编解码、连接、会话）
├── src/gateway/     REST + SSE + 回放
└── README.md
```

**实测数据**：

- 2254 帧解析通过
- 54 条真实消息解码
- 16 个用户 uid → 昵称
- 真连钉钉成功（`/reg` 200，拿到路由 `HZ`）

### 工具链

| 目录 | 内容 |
|---|---|
| `tools/mitm/` | MITM 代理（单域名拦截、增量落盘、Clash 规则）|
| `tools/disasm/` | PE 解析、交叉引用、导出表、反汇编 |
| `tools/extract-token.ts` | 从抓包提取登录态 |
| `apps/preview/` | 极简预览页 |

## 三、未完成

### 1. 会话 ID 的传递方式（阻塞发送）

`IDLSend/send` 的 body 里**没有** `conversationId`。逐字节差分确认，唯一变动字段是 `sendMsgUUID`。

**后果**：发送请求返回 400。

**下一步**：需 Ghidra 分析 `IDLSend` 编码函数，或实测「同一会话连发两条」的差分。

### 2. 扫码登录（阻塞自动化）

```
generateForConfirmLogin → lwpqr_<UUID>      ✅ 已实现
（用户扫码）
loginByFido            → token              ❌ 需 x5-sign 签名
```

`x5-sign` 由 `SecurityGuardSDK64.dll` 生成，未加壳但逆向成本高。

**备选方案**：旁路提取（用户正常登录，MITM 抓 token）。

### 3. Token 生命周期

实测：数小时后失效（`/reg` 返回 401）。

**影响**：每次使用前需重新提取。

## 四、技术结论

### 可行的

- ✅ LWP 协议层完全可复刻（标准 TLS WebSocket + 文本帧）
- ✅ 消息编解码可复刻（字节级验证）
- ✅ 网关架构可运行

### 受限的

- ⚠️ 发送需解决会话上下文
- ⚠️ 登录需 x5-sign（或旁路）
- ⚠️ Token 短期有效

### 不建议的

- ❌ 逆向阿里安全 SDK：配置驱动 + Detours 监控，投入产出比差
- ❌ 深改 telegram-tt：工作量远超预期

## 五、后续选择

### A. 旁路提取（推荐）

```bat
tools\capture-login.bat
```

用户正常用钉钉，MITM 抓 token，30 秒。接受「每次使用前跑一次」。

### B. 登录代理

网关启动隐藏的钉钉窗口，用户在其中扫码，网关从内存取 token。
不逆向任何东西，但要多维护一个进程。

### C. 继续逆向

用 Ghidra 啃 `getSecurityToken`。工作量以天计，且算法可能改版。

## 六、资产清单

```
teletalk/
├── apps/
│   ├── server/          网关（可用）
│   └── preview/         预览页
├── packages/shared/     类型定义
├── tools/
│   ├── mitm/            MITM 抓包环境
│   ├── disasm/          反汇编工具
│   └── extract-token.ts 登录态提取
├── docs/research/
│   └── dingtalk-protocol/   全部协议文档
└── scripts/             测试与验证脚本
```

## 七、快速上手

```bash
# 1. 提取登录态
tools\capture-login.bat

# 2. 启动网关
pnpm --filter @teletalk/server dev

# 3. 打开预览
http://127.0.0.1:8787/

# 4. 验证编解码
npx tsx scripts/test-codec.ts <抓包目录>
npx tsx scripts/verify-send.ts <抓包目录>
```