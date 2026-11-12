# Ghidra 逆向 SDK 工作流

## 前置

- Ghidra 11.4.2（解压到任意目录，`ghidraRun.bat` 在 `support/` 同级）
- JDK 21+（已验证 JDK 25 可用）

## 1. 创建项目并导入

```powershell
$GHIDRA = "C:\Tools\ghidra_11.4.2_PUBLIC"
$SDK = "C:\Program Files (x86)\DingDing\main\current_new\SecurityGuardSDK64.dll"
$PROJ = "C:\Users\xrl\Codes\teletalk\.ghidra\proj"

& "$GHIDRA\support\analyzeHeadless.bat" $PROJ Teletalk `
  -import $SDK `
  -overwrite
```

首次分析 10 MB 的 DLL 需要 5–20 分钟（取决于机器）。

## 2. 导出目标函数反编译

`tools/ghidra/TeletalkSdk.java` 已内置目标 RVA 列表：

| RVA | 函数 |
|---|---|
| `0x182380` | getSecurityToken |
| `0x17fa30` | initUMID |
| `0x182d20` | getCompatibelDcpToken |
| `0xf8c50` | QueryInterface |
| `0x169000` … `0x176a10` | ITrafficFilter 虚表 8 个方法 |
| `0x89e20` | 签名路径 key 相关 |
| `0x81490` | 签名路径核心调用 |
| `0x168e60` | ITrafficFilter 构造 |
| `0x17a230` | ITrafficFilter 工厂 |

```powershell
& "$GHIDRA\support\analyzeHeadless.bat" $PROJ Teletalk `
  -process SecurityGuardSDK64.dll `
  -noanalysis `
  -scriptPath tools\ghidra `
  -postScript TeletalkSdk.java "$PWD\.ghidra\out"
```

产出：

```
.ghidra/out/
├── summary.txt              函数清单（按大小排序）+ 导出表
└── funcs/
    ├── 0x182380_getSecurityToken.c
    ├── 0x16fb00_*.c
    └── ...
```

## 3. CFF 映射分析

`tools/ghidra/CffMap.java` 扫描函数体内的 `xor imm` 密钥与间接跳转：

```powershell
& "$GHIDRA\support\analyzeHeadless.bat" $PROJ Teletalk `
  -process SecurityGuardSDK64.dll `
  -noanalysis `
  -scriptPath tools\ghidra `
  -postScript CffMap.java "$PWD\.ghidra\out\cff-182380.txt" 182380
```

## 4. 现有的轻量工具（无需 Ghidra）

```bash
SDK="C:/Program Files (x86)/DingDing/main/current_new/SecurityGuardSDK64.dll"

# 跳板穿透
npx tsx tools/disasm/follow.ts "$SDK" 169000 --scan --chain

# 展平状态链遍历
npx tsx tools/disasm/walk-cff.ts "$SDK" 1824f1 50

# CFF 密钥统计
npx tsx tools/disasm/cff-scan.ts "$SDK" 182380 300000
```

## 已知结论（第二轮）

- `getSecurityToken` 是 **217 状态**的控制流展平（`[rsp+68h]` 状态值，`xor 0xBB` 映射，跳转表 16 字节/项）
- 每个状态块自带一个常量算术跳板
- 实际业务逻辑在状态块之间的数据依赖里，需要还原状态机才能读

## 输出目录约定

`.ghidra/` 已在 `.gitignore` 中（包含私有项目文件与二进制分析产物）。
