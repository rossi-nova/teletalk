/**
 * 在 DLL 中搜索字符串并查找其引用点（xref）
 *
 * 用法：
 *   tsx xref.ts <dll> <字符串> [--limit N]
 */
import { parsePE, rvaToOffset, offsetToRva } from './pe.js';

const [file, needle, ...rest] = process.argv.slice(2);
if (!file || !needle) {
  console.error('用法: tsx xref.ts <dll> <字符串> [--limit N]');
  process.exit(1);
}
const limitArg = rest.indexOf('--limit');
const limit = limitArg >= 0 ? Number(rest[limitArg + 1]) : 10;

const { info, buf } = parsePE(file);
const target = Buffer.from(needle, 'utf8');

// 1) 找字符串位置
const hits: number[] = [];
let p = 0;
while ((p = buf.indexOf(target, p)) !== -1) {
  hits.push(p);
  p += 1;
}
console.log(`字符串 "${needle}" 出现 ${hits.length} 次`);

for (const off of hits.slice(0, 5)) {
  const rva = offsetToRva(info.sections, off);
  console.log(`\n  文件偏移 0x${off.toString(16)}  RVA 0x${rva?.toString(16)}`);
  // 前后上下文
  const ctx = buf.slice(Math.max(0, off - 40), off + target.length + 40);
  console.log(`  上下文: ${JSON.stringify(ctx.toString('latin1'))}`);
}

// 2) 找引用：LEA 指令形如 48 8D 0D/15 <rel32>
console.log('\n=== 查找代码段中的引用 ===');
const text = info.sections.find((s) => s.name === '.text');
if (!text) { console.log('无 .text 段'); process.exit(0); }

let found = 0;
const textStart = text.rawPointer;
const textEnd = text.rawPointer + text.rawSize;

for (const off of hits) {
  const rva = offsetToRva(info.sections, off);
  if (rva === null) continue;

  for (let i = textStart; i < textEnd - 7 && found < limit; i++) {
    // 48 8D 0D/15/1D/05 <rel32>  (lea rcx/rdx/rbx/rax, [rip+rel32])
    if (buf[i] !== 0x48 || buf[i + 1] !== 0x8d) continue;
    const modrm = buf[i + 2]!;
    if ((modrm & 0xc7) !== 0x05) continue; // [rip+disp32]
    const rel = buf.readInt32LE(i + 3);
    const insnRva = offsetToRva(info.sections, i);
    if (insnRva === null) continue;
    const targetRva = insnRva + 7 + rel;
    if (targetRva !== rva) continue;

    console.log(`  引用 @ 文件 0x${i.toString(16)}  RVA 0x${insnRva.toString(16)}  → "${needle}"`);
    found++;
    break;
  }
}
if (!found) console.log('  未找到直接 LEA 引用');
