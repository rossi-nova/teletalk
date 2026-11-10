# 抓包样本

把抓到的请求脱敏后存成 JSON 文件放在这里，用 `pnpm probe <文件名>` 重放。

## 脱敏规则（必须遵守）

| 字段 | 处理 |
|------|------|
| cookie / token / 手机号 / 姓名 / userid | 替换为 `{{DT_COOKIE}}`、`{{DT_TOKEN}}`、`<redacted>`，真实值放本地 `.env` |
| 群名 / 会话名 / 消息正文 | 换成占位文本，如 `"<群名>"`、`"probe message"` |
| 图片/文件 | 只保留 URL 的域名与路径结构，参数值脱敏 |

## 模板

```json
{
  "id": "M1",
  "note": "单聊发送文本：观察签名头与 clientMsgId",
  "method": "POST",
  "url": "https://<host>/<path>",
  "headers": {
    "content-type": "application/json",
    "cookie": "{{DT_COOKIE}}"
  },
  "body": "{\"text\":\"probe message\"}"
}
```
