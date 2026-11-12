/**
 * 分析状态槽位的层级结构
 *
 * 6 个槽位（rsp+2C/30/34/38/3C/64/68）分别代表什么？
 * 假设：某些槽位是"主状态"，决定大块；某些是"子状态"，决定小块内的分支。
 *
 * 方法：统计每个槽位的状态值范围与转移模式。
 */
import { Decoder, Formatter, FormatterSyntax, Mnemonic } from 'iced-x86';
import { parsePE, rvaToOffset } from './pe.js';

const [, , file, entryHex, rangeHex] = process.argv;
const entry = parseInt(entryHex!, 16);
const range = parseInt(rangeHex ?? '0x6000', 16);
const { buf, info } = parsePE(file!);
const fmt = new Formatter(FormatterSyntax.Nasm);

const start = rvaToOffset(info.sections, entry)!;
const end = start + range;

interface Mark {
  rva: number;
  slot: string;
  state: number;
  insn: string;
}

const marks: Mark[] = [];
let cur = start;
let insnCount = 0;

while (cur < end && insnCount < 100000) {
  const dec = new Decoder(64, buf.slice(cur, cur + 16), 0);
  dec.ip = BigInt(cur - start + entry);
  const ins = dec.decode();
  if (ins.code === 0) { cur += 1; continue; }
  insnCount++;
  const text = fmt.format(ins);
  const ip = Number(ins.ip);

  const m = text.match(/^mov dword \[rsp\+([0-9A-Fa-f]+)h?\],([0-9A-Fa-f]+)h?$/);
  if (m) {
    marks.push({ rva: ip, slot: m[1]!.toLowerCase(), state: parseInt(m[2]!, 16), insn: text });
  }
  cur += ins.length;
}

console.log(`扫描完成: ${insnCount} 指令, ${marks.length} 个状态写入\n`);

// 按槽位分组
const bySlot = new Map<string, Mark[]>();
for (const m of marks) {
  if (!bySlot.has(m.slot)) bySlot.set(m.slot, []);
  bySlot.get(m.slot)!.push(m);
}

console.log('=== 按槽位统计 ===\n');
const slotStats = [...bySlot.entries()].sort((a, b) => b[1].length - a[1].length);
for (const [slot, list] of slotStats) {
  const vals = list.map((m) => m.state);
  const uniq = new Set(vals);
  const min = Math.min(...vals);
  const max = Math.max(...vals);
  console.log(`[rsp+${slot}h]  写入 ${list.length} 次，唯一值 ${uniq.size} 个，范围 0x${min.toString(16)}–0x${max.toString(16)}`);
}

console.log('\n=== 每个槽位的状态值样本 ===\n');
for (const [slot, list] of slotStats) {
  const vals = [...new Set(list.map((m) => m.state))].sort((a, b) => a - b);
  console.log(`[rsp+${slot}h]:`);
  console.log('  ' + vals.slice(0, 40).map((v) => '0x' + v.toString(16).padStart(2, '0')).join(' '));
  if (vals.length > 40) console.log(`  ...共 ${vals.length} 个`);
  console.log('');
}

// 检查槽位间的共现模式（同一地址附近有多个槽位写入 = 状态转移）
console.log('=== 状态转移检测（相邻 200 字节内的多槽位写入）===\n');
let transfers = 0;
for (let i = 0; i < marks.length - 1; i++) {
  const a = marks[i]!;
  const b = marks[i + 1]!;
  if (a.slot !== b.slot && b.rva - a.rva < 200) {
    if (transfers < 40) {
      console.log(`  0x${a.rva.toString(16)} [${a.slot}]←0x${a.state.toString(16)}  →  0x${b.rva.toString(16)} [${b.slot}]←0x${b.state.toString(16)}  (间隔 ${b.rva - a.rva}B)`);
    }
    transfers++;
  }
}
console.log(`\n共 ${transfers} 处跨槽位转移`);

// 唯一值最多的槽位 = 主状态
console.log('\n=== 层级推断 ===\n');
const sorted = [...slotStats].sort((a, b) => {
  const ua = new Set(a[1].map((m) => m.state)).size;
  const ub = new Set(b[1].map((m) => m.state)).size;
  return ub - ua;
});
for (const [slot, list] of sorted) {
  const uniq = new Set(list.map((m) => m.state)).size;
  const role = uniq > 100 ? '主状态（大块）' : uniq > 20 ? '中状态' : '子状态（小块分支）';
  console.log(`  [rsp+${slot}h]  唯一值 ${uniq}  → ${role}`);
}