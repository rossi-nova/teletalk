# LWP 抓包样本

2026-11-10 从本机钉钉 Windows 客户端 9.0.5-Release.261029005 抓取，端点 `tls-desktop.dingtalk.com:443`。

## 内容

- `parsed.txt` —— `parse-lwp.mjs` 的解析输出，392 帧，含请求 URI 统计与前 20 条请求的完整头与 body

## 敏感信息

样本中的 `token`、`did`、`orgId` 等为真实值，**未做脱敏**，仅用于本地分析。
本目录已在 `.gitignore` 中排除，不会进入版本库。
