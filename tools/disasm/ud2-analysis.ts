/**
 * ud2 陷阱分析
 *
 * 目的：7301 个 ud2 密布全 SDK。分析它们的分布模式，
 * 判断混淆器的结构（全部是错误路径，还是也有正常用作陷阱的）
 */
import { readFileSync } from 'node:fs';
import { parsePE, offsetToRva, rvaToOffset } from './pe.js';

const { buf, info } = parsePE('C:/Program Files (x86)/DingDing/main/current_new/SecurityGuardSDK64.dll');
const text = info.sections.find((s) => s.name === '.text')!;

const lo = text.rawPointer;
const hi = lo + text.rawSize;

const ud2: number[] = [];
for (let i = lo; i < hi - 1; i++) {
  if (buf[i] === 0x0f && buf[i + 1] === 0x0b) ud2.push(offsetToRva(info.sections, i)!);
}

console.log(`ud2 总数: ${ud2.length}`);
console.log(`.text 大小: 0x${text.rawSize.toString(16)} (${text.rawSize} 字节)`);
console.log(`平均每 KB: ${(ud2.length / (text.rawSize / 1024)).toFixed(2)} 个\n`);

// 分布统计（每 0x10000 一段）
const buckets = new Map<number, number>();
for (const r of ud2) {
  const b = Math.floor(r / 0x10000) * 0x10000;
  buckets.set(b, (buckets.get(b) ?? 0) + 1);
}
console.log('=== 按 64KB 段分布（前 30 段）===');
[...buckets].sort((a, b) => b[1] - a[1]).slice(0, 30).forEach(([b, n]) => {
  console.log(`  0x${b.toString(16).padStart(6, '0')}: ${n} 个 ${'#'.repeat(Math.min(50, Math.ceil(n / 10)))}`);
});

// 检查 ud2 前后的字节模式（找规律）
console.log('\n=== ud2 前后 4 字节模式统计 ===');
const patterns = new Map<string, number>();
for (const r of ud2.slice(0, 3000)) {
  const off = rvaToOffset(info.sections, r)!;
  if (off < 4 || off + 6 >= buf.length) continue;
  const before = buf.subarray(off - 4, off).toString('hex');
  const after = buf.subarray(off + 2, off + 6).toString('hex');
  const key = `${before}|${after}`;
  patterns.set(key, (patterns.get(key) ?? 0) + 1);
}
console.log('最常见的模式:');
[...patterns].sort((a, b) => b[1] - a[1]).slice(0, 15).forEach(([k, n]) => {
  console.log(`  ${k}  ×${n}`);
});

// 检查是否紧跟 ret（ud2 后就是 ret = "不该到这儿"）
let nextRet = 0;
for (const r of ud2) {
  const off = rvaToOffset(info.sections, r)!;
  if (buf[off + 2] === 0xc3 || buf[off + 2] === 0xcc) nextRet++;
}
console.log(`\nud2 后紧跟 ret/int3: ${nextRet} / ${ud2.length} (${(nextRet / ud2.length * 100).toFixed(1)}%)`);

// 检查 ud2 前面是否是跳板特征（push/ret 或 call/pop）
console.log('\n=== 样本（前 10 个 ud2 的上下文）===');
for (const r of ud2.slice(0, 10)) {
  const off = rvaToOffset(info.sections, r)!;
  const s = Math.max(0, off - 16);
  const ctx = buf.subarray(s, off + 16);
  console.log(`  0x${r.toString(16)}: ${ctx.toString('hex').match(/../g)!.join(' ')}`);
}