# teletalk MITM 抓包环境

用于抓取钉钉客户端的明文流量，服务于 `docs/research/dingtalk-protocol/`。

## 组成

| 文件 | 作用 |
|------|------|
| `certs/ca.crt` `certs/ca.key` | 本地根证书（**私钥不可外传**） |
| `certs.mjs` | 按域名动态签发站点证书，缓存在 `certs/sites/` |
| `proxy.mjs` | MITM 代理：CONNECT → 动态签发 → 解密 → 落盘 |
| `install-ca.ps1` / `uninstall-ca.ps1` | 装/卸根证书到 `CurrentUser\Root` |
| `setup-proxy.ps1` | 切换系统代理（含备份与还原） |

默认只解密 `*.dingtalk.com`、`*.dingtalkapps.com`、`*.alicdn.com`，其余直通。

## 已验证

- 站点证书签发（含 SAN、AKI）✔
- TLS 握手与解密 ✔
- 明文 HTTP 落盘 ✔

## 使用步骤

**开抓前先记下当前系统代理**。本机原有 `127.0.0.1:7897`，脚本会自动备份。

```powershell
# 1. 装根证书（当前用户，无需管理员）
powershell -ExecutionPolicy Bypass -File install-ca.ps1

# 2. 起代理
node proxy.mjs --port 8888

# 3. 另开窗口，切系统代理
powershell -ExecutionPolicy Bypass -File setup-proxy.ps1 -Enable -Port 8888

# 4. 重启钉钉（必须先退出，包括托盘图标）
taskkill /IM DingTalk.exe /F
# 手动启动钉钉，登录

# 5. 抓完还原
powershell -ExecutionPolicy Bypass -File setup-proxy.ps1 -Disable
powershell -ExecutionPolicy Bypass -File uninstall-ca.ps1
```

## 产物

`captures/run-<时间戳>/` 下按 `<序号>-<域名>-<方向>.bin` 命名：

- `c2s` 客户端→服务端
- `s2c` 服务端→客户端

长连接（`lws-desktop.dingtalk.com`）抓到的是 **WebSocket 帧**，需要另行解析。

## 已知风险

- 钉钉有进程守护，强制结束可能自动重启。
- 若长连接不走系统代理（配置项 `enable_proxy_use_domain_directly=1`），需改用其它手段（TLS keylog / 全局透明代理）。
- 抓包内容含账号凭据，**不可提交**（`.gitignore` 已排除 `captures/`）。
