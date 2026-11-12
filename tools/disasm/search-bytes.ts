/** 精确搜索字节序列（支持掩码） */
import { readFileSync } from 'node:fs';
import { parsePE, offsetToRva } from './pe.js';

const [, , file, hexPattern] = process.argv;
const want = Buffer.from(hexPattern!.replace(/\s/g, ''), 'hex');
const { buf, info } = parsePE(file!);

console.log(`搜索 ${want.toString('hex')} 在 ${file}`);
let n = 0;
for (let i = 0; i <= buf.length - want.length; i++) {
  if (buf[i] !== want[0]) continue;
  if (buf.compare(want, 0, want.length, i, i + want.length) === 0) {
    const rva = offsetToRva(info.sections, i);
    let sec = '';
    for (const s of info.sections) {
      if (i >= s.rawPointer && i < s.rawPointer + s.rawSize) { sec = s.name; break; }
    }
    console.log(`  off=0x${i.toString(16)}  RVA=${rva === null ? '?' : '0x' + rva.toString(16)}  [${sec}]`);
    // 上下文
    const a = Math.max(0, i - 16);
    const b = Math.min(buf.length, i + want.length + 16);
    console.log(`    ctx: ${buf.slice(a, b).toString('hex').replace(/(..)/g, '$1 ')}`);
    if (++n >= 20) break;
  }
}
console.log(`共 ${n} 处`);
