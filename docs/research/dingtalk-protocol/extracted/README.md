# 提取产物

由运行在本机的钉钉 Windows 客户端（9.0.2.261013001）`MainFrame.dll` 静态提取。

| 文件 | 说明 |
|------|------|
| `live-protocol.proto` | 从 4 个内嵌 `FileDescriptorProto` 还原的传输层 proto |
| `routes.md` | 1193 条 RPC 路由（35 个服务） |
| `scan-descriptors.cjs` | 扫描 PE 内的 descriptor |
| `export-proto.cjs` | descriptor → .proto |
| `extract-routes.cjs` | 提取路由表 |
| `desc-list.json` `desc-all.bin` | 中间产物（可从脚本重新生成） |

## 复现

```bash
cd docs/research/dingtalk-protocol/extracted
node scan-descriptors.cjs "C:/Program Files (x86)/DingDing/main/current/MainFrame.dll"
node export-proto.cjs     "C:/Program Files (x86)/DingDing/main/current/MainFrame.dll"
node extract-routes.cjs   "C:/Program Files (x86)/DingDing/main/current/MainFrame.dll"
```

脚本只读文件，不修改、不执行目标程序。

## 已知边界

- 业务消息（`syncidl` / `wukongidl`）的 **protobuf 字段号未提取**：这些字段号编译为机器码立即数，字符串池中只有字段名。
- `web_content.dat` 为 ZipCrypto 加密，密码由服务端下发，本地无法解出。
