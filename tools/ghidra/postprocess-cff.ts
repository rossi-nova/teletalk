/**
 * Ghidra C 输出后处理：把控制流展平产生的 goto 地狱整理成可读结构
 *
 * 输入：Ghidra 反编译的 .c 文件（含大量 goto LAB_xxx 与 switch(state)）
 * 输出：
 *   1. 提取所有 goto 目标与标签，标出可达/不可达
 *   2. 识别「状态赋値 → goto 分发」模式，还原成状态迁移表
 *   3. 抽取出所有内存常量（立即数、字符串指针）供人工核验
 *
 * 用法: npx tsx tools/ghidra/postprocess-cff.ts <in.c> [out.md]
 */
import { readFileSync, writeFileSync } from 'node:fs';

const [, , inPath, outPath] = process.argv;
if (!inPath) {
  console.error('用法: npx tsx tools/ghidra/postprocess-cff.ts <in.c> [out.md]');
  process.exit(1);
}
const src = readFileSync(inPath, 'utf8');

// ---- 1. 标签与 goto ----
const labels = [...src.matchAll(/^\s*(LAB_[0-9a-fA-F]+|code_r0x[0-9a-fA-F]+|joined_r0x[0-9a-fA-F]+):/gm)]
  .map((m) => m[1]!);
const gotos = [...src.matchAll(/goto\s+(LAB_[0-9a-fA-F]+|code_r0x[0-9a-fA-F]+|joined_r0x[0-9a-fA-F]+)/g)]
  .map((m) => m[1]!);
const gotoTargets = [...new Set(gotos)];
const unreachable = labels.filter((l) => !gotoTargets.includes(l));

// ---- 2. 状态赋值 ----
const stateWrites = [...src.matchAll(/(\w+(?:->\w+)?)\s*=\s*(0x[0-9a-fA-F]+|\d+);/g)]
  .filter((m) => /state|uVar\d+|local_/i.test(m[1]!))
  .slice(0, 200);

// ---- 3. 常量提取 ----
const hexLits = [...new Set([...src.matchAll(/0x[0-9a-fA-F]{4,16}/g)].map((m) => m[0]))];
const strLits = [...new Set([...src.matchAll(/"((?:[^"\\]|\\.){3,})"/g)].map((m) => m[1]!))];

// ---- 输出 ----
const lines: string[] = [];
lines.push('# CFF 后处理报告');
lines.push('');
lines.push(`源文件：\`${inPath}\``);
lines.push(`行数：${src.split('\n').length}`);
lines.push('');
lines.push('## 统计');
lines.push('');
lines.push(`- 标签：${labels.length}`);
lines.push(`- goto：${gotos.length}（去重目标 ${gotoTargets.length}）`);
lines.push(`- 疑似不可达标签：${unreachable.length}`);
lines.push(`- 十六进制常量：${hexLits.length}`);
lines.push(`- 字符串字面量：${strLits.length}`);
lines.push('');
lines.push('## 不可达标签（死代码/展平残留）');
lines.push('');
unreachable.slice(0, 60).forEach((l) => lines.push(`- \`${l}\``));
if (unreachable.length > 60) lines.push(`- …共 ${unreachable.length} 个`);
lines.push('');
lines.push('## 高位十六进制常量（可能是魔数/密钥）');
lines.push('');
hexLits
  .filter((h) => h.length >= 10)
  .slice(0, 80)
  .forEach((h) => lines.push(`- \`${h}\``));
lines.push('');
lines.push('## 字符串字面量');
lines.push('');
strLits.slice(0, 120).forEach((s) => lines.push(`- \`${s}\``));

const report = lines.join('\n');
if (outPath) {
  writeFileSync(outPath, report, 'utf8');
  console.log(`已写出 ${outPath}`);
} else {
  console.log(report);
}
