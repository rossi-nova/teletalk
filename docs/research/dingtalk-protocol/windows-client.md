# 钉钉 Windows 客户端协议分析（9.0.2.261013001）

> 分析日期：2026-11-10。来源：本机安装的 `C:\Program Files (x86)\DingDing\main\current` 与 `%APPDATA%\DingTalk\log`。
> 手段：静态字符串提取 + descriptor 解析 + 客户端自身日志。**未抓包、未注入、未调试进程。**

## 1. 客户端形态

- **Qt5 + C++ 原生**，非 Electron。核心 `MainFrame.dll`（171 MB）。
- 内嵌 Chromium 内容层（`web_contents_helper.cc`、`cef_debug.log`），聊天框等界面 Web 渲染，**网络与业务逻辑在 C++ 层**。
- 有 JS 引擎运行时（`eapp_runtime` 的 V8 blob + `jsi/jsi.dll`）；`jsi/*.amr` 为 mini-app 包（未加密 ZIP，内含 tar + CERT.json + Manifest.xml）。
- 加固：`AliProtectCollina.dll`、`AlibabaProtectCon.exe`、`SecurityGuardSDK64.dll`。
- Web 资源 `web_content.dat`（102 MB）为 **ZipCrypto 加密 ZIP**，密码服务端下发，本地 JS 不可直接取得。

## 2. 网络架构

| 层 | 名称 | 说明 |
|----|------|------|
| 长连接 | **gaea / LWP**（Long WebSocket Protocol） | `libgaea.dll`，`4.3.14-dingtalk.atlas4-SNAPSHOT` |
| 底层库 | **Bifrost / mars**（微信开源 mars 的变体） | 路径 `mars/stn/proto/http2_packer.cc` |
| 传输 | TLS 443 + WebSocket 二进制帧 | 端点 `lws://<ip>:443?isp=&pub-key=<64hex>&rm=&sni=dk&source=aladdin` |
| 编码 | **protobuf**（含完整 Reflection 运行时） | `google/protobuf/descriptor.proto` 已链接 |
| 心跳 | 42 秒 | `cmdid:(0, )`，帧 `len(S:23/23)` |
| 域名 | `lws-desktop.dingtalk.com`、`tls-desktop.dingtalk.com`、`n.dingtalk.com` | |

`lws://` 是自定义 scheme，实际为 TLS + WebSocket，Node 侧用 `ws` 即可建连。

## 3. 请求标识

```
sid     = k0_<32hex>_<48hex>        会话密钥，每连接独有
ua_id   = 16 位数字                  用户代理 ID，登录后下发
mid     = 8 位十六进制               请求序列号（4 字节递增）
uri     = /r/<Service>/<method>      RPC
uri     = /s/<name>                 订阅/推送
uri     = /!                        心跳
```

## 4. 协议定义（已提取）

`MainFrame.dll` 内嵌 4 个 protobuf `FileDescriptorProto`，明文、可直接解析。完整的 proto 见 `extracted/live-protocol.proto`，关键结构：

```protobuf
// headerV1.proto —— 每个长连接帧的外壳
message Header {
  string topic = 1;        // 路由 topic
  int32  priority = 2;
  int32  statusCode = 3;
  string sdkVersion = 4;
  string appVersion = 5;
  string messageId = 6;
  int32  subType = 7;
  string userId = 8;       // 鉴权字段
  string token = 9;        // 鉴权字段
  int32  monitorTag = 10;
  Config config = 11;
  int32  platform = 12;
}
```

**`Header.userId` + `Header.token` 是鉴权核心**，即日志中的 `ua_id` / `sid`。

其余三个：`bodyV1.proto`（Msg/Command/Request/Subscribe/P2P/Report/Monitor）、`sysDataV1.proto`（TopicUser/TopicStat/TextMessage/Config）、`google/protobuf/descriptor.proto`。

## 5. RPC 路由表（已提取）

`extracted/routes.md`：**35 个服务、1193 条路由**，其中 `Adaptor` 内含 **266 个业务接口、1007 个方法**。

IM 核心：

| URI | 用途 |
|-----|------|
| `/r/IDLSend/send` | 发送消息（`enable_retry=1`） |
| `/r/IDLSend/forward` | 转发 |
| `/r/IDLMessage/listMessagesPaginationV2` | 历史消息分页 |
| `/r/IDLMessage/getMessageByIdWithCidV2` | 单条取消息 |
| `/r/IDLConversation/listNewestExtV4` | 会话列表 |
| `/r/IDLConversation/getByIds` | 会话详情 |
| `/r/IDLConversation/listMembersV3` | 群成员 |
| `/r/IDLMessageStatus/updateToReadV2` | 已读回执 |
| `/r/Sync/getDiff` | 增量同步 |
| `/r/FileUpload/frag` | 文件分片上传 |
| `/r/FileDown/get` | 文件下载 |
| `/s/sync` `/s/synca` `/s/feynman` `/s/para` | 推送订阅 |
| `/reg` `/reg/init` | 连接注册 |

## 6. 已知的分析开关（未启用）

`libgaea.dll` 内存在：`c_enable_dump_request`、`raw_lwp_body:`、`raw_lwp_response_base64=`、`ssl_log_rsa_client_key_exchange`、`nss_keylog_int`、`CONF_dump_fp`。

配置由**服务端下发**（日志 `server version 202107201728143780`），磁盘无 `gaea.conf`，不能靠改本地文件开启。

## 7. 结论

| 项 | 判定 |
|----|------|
| 传输层 | ✅ 标准 TLS WebSocket，可复刻 |
| 帧外壳 | ✅ `headerV1.proto` 已提取 |
| RPC 路由 | ✅ 1193 条已提取 |
| 业务消息 schema | ⚠️ 仅名字层（618 个 IDL 类名、字段名可见），**字段号（tag）未提取** |
| 握手加密 | ⚠️ `pub-key` / `base64_app_pub_key` 协商算法待在二进制中定位 |
| 登录态 | ⚠️ `userId` + `token` 来源需实测 |

## 8. 下一步

1. 定位 `Header.token` 的生成链路（登录流程在 `/reg` 前后）。
2. 从 `MainFrame.dll` 的 `gaeaidl` RTTI 区块提取业务 IDL 的字段号（或运行时 dump 反射信息）。
3. 用已提取的 Header 结构搭最小 WebSocket 客户端，验证能否通过握手。

## 复现

```bash
node docs/research/dingtalk-protocol/extracted/scan-descriptors.cjs   # 扫 descriptor
node docs/research/dingtalk-protocol/extracted/export-proto.cjs       # 还原 proto
```
