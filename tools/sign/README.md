# SDK 运行时工具

对 `SecurityGuardSDK64.dll` 的动态分析工具集。

> 静态逆向受跳板混淆限制（见 `docs/research/dingtalk-protocol/sdk-reverse-round3.md`），
> 本目录走运行时路线：读取钉钉进程中 SDK 的内存状态。

## 构建

需要 VS 2022 x64 工具链：

```powershell
$vcvars = "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
cmd /c "`"$vcvars`" && cd build && cl /nologo /O2 /Fe:<name>.exe ..\<src>.c advapi32.lib Psapi.lib"
```

`sdk.c` 编译出的工具需要把 `SecurityGuardSDK64.dll` 复制到同目录。

## 工具

| 源文件 | 产物 | 用途 | 状态 |
|---|---|---|---|
| `x5-dump.c` | `x5-dump.exe` | **提取 x5-sign**（核心工具）| ✅ 验证通过 |
| `hunt-token.c` | `hunt-token.exe` | 按特征串搜索 token | ✅ |
| `state-check.c` | `state-check.exe` | SDK 运行时状态检查 | ✅ |
| `mem-probe.c` | `mem-probe.exe` | 模块基址与 PE 头读取 | ✅ |
| `data-probe.c` | `data-probe.exe` | `.data` 段字符串扫描 | ✅ |
| `rev-object.c` | `rev-object.exe` | token 持有者反查 | ✅ |
| `deep-obj.c` | `deep-obj.exe` | 对象字段深度 dump | ✅ |
| `token-analyze.c` | `token-analyze.exe` | base64 解码与结构分析 | ✅ |
| `list-dids.c` | `list-dids.exe` | 枚举内存里全部 did 候选（含上下文）| ✅ |
| `dump-frames.c` | `dump-frames.exe` | dump 内存里的 LWP 帧 blob | ✅ |
| `dump-lwp-reqs.c` | `dump-lwp-reqs.exe` | 按 URI 过滤扫 LWP 请求帧 | ✅ |
| `dump-around-did.c` | `dump-around-did.exe` | dump did 命中点附近内存 | ✅ |
| `sign.c` | `teletalk-sign.exe` | SDK 导出直接调用 | ⚠️ ABI 未确认 |
| `abi-probe.c` | `abi-probe.exe` | initUMID 参数枚举 | ✅ 结论见文档 |
| `hwbp.c` / `hwbp2.c` | `hwbp.exe` | 硬件断点捕获 | ⚠️ 会冻结钉钉，需谨慎 |

## 核心用法

```powershell
# 提取当前 x5-sign（钉钉需在运行）
.\build\x5-dump.exe

# JSON 格式（供程序调用）
.\build\x5-dump.exe --json
```

输出示例：

```json
{"pid":5668,"tokens":[{"addr":"0x2362c413780","len":102,
  "value":"wzMK2c002xAAIUSpEi5MzgbF8qaUsUShTmNrh+l+9LptNeixSpH4QiUVnoOJGfbjDPjUv653/9Wn64ClF/tAxRPkpxFEsUShRLFEoU"}]}
```

## 重要限制

- **签名缓存稳定**：提取到的值是 SDK 缓存，不随请求刷新
- **签名与请求绑定**：每个 RPC 方法可能对应不同的 factors，缓存值未必通用
- **需要钉钉运行中**：进程退出后内存消失

## 安全性

- 只读内存（`ReadProcessMemory`），不修改目标进程
- `hwbp` 会附加调试器并**暂停钉钉**，仅用于短时捕获

## 与网关的集成

`apps/server/src/lwp/x5-sign.ts` 调用 `x5-dump.exe --json`，
把提取到的签名注入 LWP 请求头。

```ts
import { getX5Headers } from './x5-sign.js';
const x5 = await getX5Headers();
// { 'x5-sign': 'wzMK2c002xAA...', 'x5-bx-version': '...', 'x5-sgext': 'win_reserve' }
```
