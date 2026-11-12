/**
 * 提取函数体内所有调用目标（含跳板外的真实调用）
 *
 * 用法: npx tsx tools/disasm/calls-in-fn.ts <file> <startRva> <endRva>
 */
import { Decoder, Formatter, FormatterSyntax, Mnemonic } from 'iced-x86';
import { parsePE, rvaToOffset } from './pe.js';

const [, , file, startHex, endHex] = process.argv;
const start = parseInt(startHex!, 16);
const end = parseInt(endHex!, 16);
const { buf, info } = parsePE(file!);
const fmt = new Formatter(FormatterSyntax.Nasm);

const direct = new Map<number, number>();   // target -> count
const indirect: string[] = [];
let cur = start;
let n = 0;

while (cur < end) {
  const off = rvaToOffset(info.sections, cur);
  if (off === null) break;
  const dec = new Decoder(64, buf.slice(off, off + 16), 0);
  dec.ip = BigInt(cur);
  const ins = dec.decode();
  if (ins.code === 0) { cur += 1; continue; }
  n++;

  if (ins.mnemonic === Mnemonic.Call) {
    const t = fmt.format(ins);
    // 直接调用：call 0000000000123456h
    const m = t.match(/^call ([0-9A-F]+)h?$/);
    if (m) {
      const target = parseInt(m[1]!, 16);
      direct.set(target, (direct.get(target) ?? 0) + 1);
    } else if (t.includes('[rel')) {
      const r = t.match(/\[rel ([0-9A-F]+)h?\]/);
      indirect.push(`0x${cur.toString(16)}  IAT ${r ? r[1] : '?'}`);
    } else {
      indirect.push(`0x${cur.toString(16)}  ${t}`);
    }
  }

  cur += ins.length;
}

console.log(`扫描 0x${start.toString(16)}..0x${end.toString(16)}: ${n} 条指令\n`);

console.log('=== 直接调用 ===');
for (const [t, c] of [...direct].sort((a, b) => b[1] - a[1]).slice(0, 25)) {
  const inSdk = t >= 0x1000 && t < 0x8dc000;
  console.log(`  0x${t.toString(16)}  ×${c}${inSdk ? '' : '  (外部/非代码)'}`);
}

console.log('\n=== 间接调用 ===');
indirect.slice(0, 20).forEach((s) => console.log('  ' + s));
if (indirect.length > 20) console.log(`  ...共 ${indirect.length} 处`);