/**
 * 利用 ud2 标记重建 getSecurityToken 的状态转移图
 *
 * 发现：每个 ud2 前面都有一条 mov [rsp+X], imm 指令——这是状态转移标记。
 * ud2 前面的有效指令才是真实逻辑所在。
 *
 * 用法: npx tsx tools/disasm/ud2-graph.ts <dll> <入口RVA> [范围字节]
 */
import { Decoder, Formatter, FormatterSyntax, Mnemonic } from 'iced-x86';
import { parsePE, rvaToOffset } from './pe.js';

const [, , file, entryHex, rangeHex] = process.argv;
const entry = parseInt(entryHex!, 16);
const range = parseInt(rangeHex ?? '0x8000', 16);
const { buf, info } = parsePE(file!);
const fmt = new Formatter(FormatterSyntax.Nasm);

const start = rvaToOffset(info.sections, entry)!;
const end = start + range;

console.log(`扫描 0x${entry.toString(16)} .. 0x${(entry + range).toString(16)}\n`);

// 收集所有 ud2，找它们前面的 mov [rsp+X], imm（状态标记）
interface StateMark {
  rva: number;
  insn: string;
  state?: number;
}

const marks: StateMark[] = [];
let cur = start;
let totalInsns = 0;

while (cur < end && totalInsns < 50000) {
  const dec = new Decoder(64, buf.slice(cur, cur + 16), 0);
  dec.ip = BigInt(cur - start + entry);
  const ins = dec.decode();
  if (ins.code === 0) { cur += 1; continue; }
  totalInsns++;
  const text = fmt.format(ins);
  const ipNum = Number(ins.ip);

  // 记录 mov [rsp+X], imm（状态赋值）
  // 格式器输出: "mov dword [rsp+64h],9Ch"
  const m = text.match(/^mov dword \[rsp\+([0-9A-Fa-f]+)h?\],([0-9A-Fa-f]+)h?$/);
  if (m) {
    marks.push({ rva: ipNum, insn: text, state: parseInt(m[2]!, 16) });
  }

  cur += ins.length;
}

console.log(`${totalInsns} 条指令, ${marks.length} 个状态标记\n`);

// 去重（连续重复的同位置标记只保留第一个）
const unique = marks.filter((m, i) => !i || m.state !== marks[i - 1]?.state || m.rva - marks[i - 1]!.rva > 50);

// 统计状态值分布
const stateDist = new Map<number, number>();
for (const m of unique) stateDist.set(m.state!, (stateDist.get(m.state!) ?? 0) + 1);

console.log(`=== 状态值分布（${unique.length} 个唯一标记）===\n`);
const sorted = [...stateDist.entries()].sort((a, b) => a[0] - b[0]);
for (const [s, n] of sorted.slice(0, 120)) {
  console.log(`  状态 0x${s.toString(16).padStart(2, '0')}  (${s.toString().padStart(3)}): ${n} 次 ${'#'.repeat(Math.min(40, n))}`);
}
if (sorted.length > 120) console.log(`  ...共 ${sorted.length} 种状态`);

console.log(`\n=== 状态链（按出现顺序，前 60 个）===\n`);
for (const m of unique.slice(0, 60)) {
  console.log(`  0x${m.rva.toString(16).padStart(8)}  ${m.insn.padEnd(35)}`);
}

// 识别每个状态块的入口（第一个 mov [rsp+X], imm 之后到下一个状态之间）
console.log(`\n=== 状态块边界 ===\n`);
let last = 0;
for (let i = 0; i < unique.length; i++) {
  const diff = i ? unique[i]!.rva - last : 0;
  if (diff > 300 || !i) {
    console.log(`  块入口 0x${unique[i]!.rva.toString(16).padStart(8)}  状态 0x${unique[i]!.state?.toString(16).padStart(2, '0')}  距前 ${diff}B`);
  }
  last = unique[i]!.rva;
}