# 扫码登录

> 更新：2026-11-10

## 协议（已确认）

### 1. 申请二维码

```
LWP /r/Adaptor/QrcodeI/generateForConfirmLogin
dt:p
len:91

body: da 00 58 <88 字节客户端标识>
```

响应：

```
200
len:45

lwpqr_2A660AC1-3799-4E41-A850-693463F16007
```

**`lwpqr_<UUID>` 即二维码内容。**

### 2. 提交扫码结果

```
LWP /r/Adaptor/QrcodeI/pushConfirmLogin
dt:p
len:148

body: 82 01 da 00 61 "oauth_k1:..." 02 da 00 2a "lwpqr_..."
```

响应 0 字节。

### 3. 换取 token

```
LWP /r/Adaptor/LoginI/loginByFido
dt:p
len:775

body: 83 01 81 01 a0 02 da 00 2a "lwpqr_..." 03 a7 "confirm" 86 0b da 01 3c "<大段 base64>"
```

**需要三个签名头**：`x5-sign` / `x5-miniuua` / `x5-umid-token`，由 `SecurityGuardSDK64.dll` 生成。

## 实现状态

| 步骤 | 状态 |
|---|---|
| 申请二维码 | ✅ `apps/server/src/lwp/qr-login.ts` |
| 渲染二维码 | ✅ 前端（待接） |
| 提交扫码结果 | ⬜ 需 oauth_k1 token（扫码后由手机端下发） |
| 换取 token | ⬜ **需 x5-sign 签名** |

## 采用方案：旁路提取

不复刻 `x5-sign`，改为：

```
用户在真实钉钉里正常登录
        ↓
MITM 代理拦截 /reg 请求
        ↓
提取 token + did
        ↓
写入网关配置
```

### 工具

| 文件 | 作用 |
|---|---|
| `tools/mitm/proxy.mjs` | 只拦截 `tls-desktop.dingtalk.com` |
| `tools/extract-token.ts` | 从抓包提取 token → `apps/server/.env` |
| `tools/capture-login.bat` | 一键流程（启动代理 → 提示重启钉钉 → 提取）|

### 使用

```bat
tools\capture-login.bat
```

前提：Clash Verge 已配置 `teletalk-merge.yaml`，`teletalk-capture` 指向 `teletalk-mitm`。

## Token 生命周期

实测：抓包获取的 token 在数小时后失效（`/reg` 返回 401）。

**因此每次使用前都需要重新提取**，除非实现完整的扫码登录（含签名）。

## 长期方案

要实现真正的"打开即用"，必须解决 `x5-sign`：

1. 逆向 `SecurityGuardSDK64.dll` 的签名算法
2. 或让网关充当钉钉客户端的登录代理（转发而非复刻）

方案 2 不违反安全机制，工程上也更可控。
