/**
 * 控制流展平（CFF）摸底：扫描函数体内的 xor imm 密钥与间接跳转分发点
 *
 * SDK 的 getSecurityToken 用 `mov eax,imm; xor eax,KEY; <算术>; jmp reg` 分发。
 * 本脚本统计密钥、分发点数量、以及每个分发点前的立即数。
 *
 * 用法: npx tsx tools/disasm/cff-scan.ts <file> <rvaHex> [指令上限]
 */
import { Decoder, Formatter, FormatterSyntax, Mnemonic } from 'iced-x86';
import { parsePE, rvaToOffset } from './pe.js';

const [, , file, rvaHex, limitArg] = process.argv;
const start = parseInt(rvaHex!, 16);
const limit = Number(limitArg ?? 200000);
const { buf, info } = parsePE(file!);
const fmt = new Formatter(FormatterSyntax.Nasm);

let cur = start;
let count = 0;
let indirectJmps = 0;
const xorKeys = new Map<string, number>();
const xorSamples: string[] = [];

while (count < limit) {
  const off = rvaToOffset(info.sections, cur);
  if (off === null) break;
  const dec = new Decoder(64, buf.slice(off, off + 16), 0);
  dec.ip = BigInt(cur);
  const ins = dec.decode();
  if (ins.code === 0) break;
  count++;
  const text = fmt.format(ins);

  // xor reg, imm
  if (ins.mnemonic === Mnemonic.Xor && ins.opCount === 2) {
    const m = text.match(/^xor (\w+),([0-9A-F]+)$/);
    if (m) {
      const k = m[2]!;
      xorKeys.set(k, (xorKeys.get(k) ?? 0) + 1);
      if (xorSamples.length < 12) xorSamples.push(`${cur.toString(16)}: ${text}`);
    }
  }
  // jmp reg
  if (ins.mnemonic === Mnemonic.Jmp && ins.opCount === 1) {
    const t = text.replace(/h$/, '');
    if (/^jmp (r\w+|e\w+)$/.test(t)) indirectJmps++;
  }

  cur += ins.length;
  if (ins.mnemonic === Mnemonic.Ret) {
    const nOff = rvaToOffset(info.sections, cur);
    if (nOff !== null) {
      const nb = buf[nOff]!;
      if (nb === 0xcc || nb === 0x00 || nb === 0x90) break;
    }
  }
}

console.log(`扫描 0x${start.toString(16)}: ${count} 条指令, 跨度 0x${(cur - start).toString(16)} 字节`);
console.log(`间接跳转（jmp reg）: ${indirectJmps} 处`);
console.log(`\nXOR 立即数密钥（按出现次数）:`);
const sorted = [...xorKeys.entries()].sort((a, b) => b[1] - a[1]);
for (const [k, n] of sorted.slice(0, 30)) {
  console.log(`  0x${k.padStart(2, '0')}: ${n} 次`);
}
console.log(`\n共 ${xorKeys.size} 种密钥`);
console.log('\n样本:');
xorSamples.forEach((s) => console.log('  ' + s));
