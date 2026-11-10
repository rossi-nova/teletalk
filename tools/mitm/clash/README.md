# Clash Verge 抓包规则

## 原理

钉钉**不读系统代理**（已实测），因此必须用 **TUN 模式**在网络层接管流量，再由规则导流到本地 MITM 代理。

```
钉钉 → (TUN 虚拟网卡) → mihomo → 规则匹配 *.dingtalk.com → 127.0.0.1:8888 (MITM)
```

## 前置

1. **开启 TUN 模式**：Clash Verge → 设置 → `TUN 模式` 打开。
   - 服务模式必须为「服务」（本机 `clash_verge_service` 已在运行）。
   - 首次开启可能要求安装服务或重启，按提示操作。
2. 启动 MITM 代理：
   ```bash
   cd C:\Users\xrl\Codes\teletalk\tools\mitm
   node proxy.mjs --port 8888
   ```

## 规则

`teletalk-merge.yaml` 贴进 Clash Verge → 配置 → **全局扩展配置** → 保存 → 重载。

## 验证

开启后重启钉钉，观察：

```bash
tail -f /tmp/mitm4.log
```

应出现 `TLS lws-desktop.dingtalk.com 443` 等条目。

## 为什么普通模式不行

普通模式下 mihomo 只接管**主动使用系统代理**的程序。钉钉走的是自己的长连接库（gaea），直接连目标 IP，绕过系统代理。
