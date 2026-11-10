# 反汇编工具

自研的轻量 PE 分析与交叉引用工具，用于研究钉钉 Windows 客户端。

> 定位：快速探查足够，深度逆向请用 Ghidra / IDA Pro。

## 工具

| 文件 | 用途 |
|---|---|
| `pe.ts` | PE 解析：节表、RVA ↔ 文件偏移 |
| `xref.ts` | 字符串交叉引用：找代码中的 LEA 引用 |
| `exports.ts` | 导出函数列表 |
| `fn-sig.ts` | 导出函数的 RVA 与入口字节 |
| `disasm-entry.ts` | 极简 x86-64 反汇编（仅常用指令） |
| `strings-in-sdk.ts` | 提取字符串并按关键词分类 |

## 用法

```bash
npx tsx tools/disasm/pe.ts <dll>
npx tsx tools/disasm/xref.ts <dll> <字符串> --limit 5
npx tsx tools/disasm/exports.ts <dll>
npx tsx tools/disasm/fn-sig.ts <dll> <函数名>
npx tsx tools/disasm/strings-in-sdk.ts <dll>
```

## 局限

- 反汇编器只识别 push/sub/mov/ret 等少数指令，不是完整解码器
- 交叉引用只扫 `48 8D 0D/15` 形式的 RIP 相对 LEA，会漏掉其它寻址方式
- 不支持控制流分析、函数边界识别

## 产出

见 `docs/research/dingtalk-protocol/reverse-notes.md`。
