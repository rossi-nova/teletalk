# 反汇编工具

自研的轻量 PE 分析与交叉引用工具，用于研究钉钉 Windows 客户端。

> 定位：快速探查足够，深度逆向请用 Ghidra / IDA Pro。
> 第二轮（2026-11-12）引入 iced-x86 完整解码器与跳板自动穿透。

## 工具

### 基础

| 文件 | 用途 |
|---|---|
| `pe.ts` | PE 解析：节表、RVA ↔ 文件偏移 |
| `xref.ts` | 字符串交叉引用：找代码中的 LEA 引用 |
| `exports.ts` | 导出函数列表 |
| `fn-sig.ts` | 导出函数的 RVA 与入口字节 |
| `strings-in-sdk.ts` | 提取字符串并按关键词分类 |

### 第二轮新增（iced-x86）

| 文件 | 用途 |
|---|---|
| `dis64.ts` | 正式反汇编：`listing` / `imports` / `exports` / `xref-iat` / `xref-rva` / `iat` |
| `follow.ts` | **混淆跳板自动穿透**（`--scan` 定位首个槽写，`--chain` 多层串联） |
| `dump-vtables.ts` | 虚表槽位 dump（按 VA → RVA 换算） |
| `fn-size.ts` | 函数规模估算（指令数 / 调用数 / 跨度） |
| `find-str.ts` | 字符串定位 + 前后字节上下文 |
| `peek.ts` | 任意 RVA 的 hex/ascii 查看 |
| `scan-vtcall.ts` | 区域内虚表间接调用（`call [reg+off]`）扫描 |

## 用法

```bash
SDK="C:/Program Files (x86)/DingDing/main/current_new/SecurityGuardSDK64.dll"

# 基础
npx tsx tools/disasm/pe.ts "$SDK"
npx tsx tools/disasm/exports.ts "$SDK"

# 正式反汇编
npx tsx tools/disasm/dis64.ts listing "$SDK" 182380 100
npx tsx tools/disasm/dis64.ts imports "$SDK" kernel
npx tsx tools/disasm/dis64.ts xref-iat "$SDK" kernel32 GetProcAddress
npx tsx tools/disasm/dis64.ts xref-rva "$SDK" 8836f00,8836e90
npx tsx tools/disasm/dis64.ts iat "$SDK" 6F75A18,6F67698

# 跳板穿透
npx tsx tools/disasm/follow.ts "$SDK" 169000 --scan --chain
VERBOSE=1 npx tsx tools/disasm/follow.ts "$SDK" 16a850 --scan

# 辅助
npx tsx tools/disasm/dump-vtables.ts
npx tsx tools/disasm/fn-size.ts "$SDK" 169000 16a850 16fb00
npx tsx tools/disasm/peek.ts "$SDK" 8de540 64
npx tsx tools/disasm/find-str.ts "$SDK" "x-sign:" vmsign
```

## 混淆跳板识别（关键）

SDK 的每个函数入口都有：

```asm
mov dword [rbp-8], 53h     ; 常量塞进栈槽
movsx rdi, word [rbx]      ; 取回（同一常量）
add rax, rdi               ; 算术运算
push rsi / ret             ; 或 jmp reg
```

`follow.ts` 用小型符号执行折叠这些常量运算，无需人工计算。

## 局限

- `xref.ts` / `disasm-entry.ts` 是初代工具，能力有限，优先用 `dis64.ts`
- 不做控制流分析：跳板穿透后不重建 CFG
- 控制流展平（如 `getSecurityToken` 用 `xor imm` 映射跳转目标）不支持，需人工或 Ghidra
- 交叉引用只扫 `lea`/`mov` RIP 相对寻址

## 产出

见 `docs/research/dingtalk-protocol/reverse-notes.md` 第 4bis 节。
