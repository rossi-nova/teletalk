/** dump 指定文件偏移附近的全部字符串与结构 */
import { readFileSync } from 'node:fs';
import { parsePE, offsetToRva } from './pe.js';

const [, , file, offHex, lenArg] = process.argv;
const start = parseInt(offHex!, 16);
const len = Number(lenArg ?? 0x800);
const buf = readFileSync(file!);
const { info } = parsePE(file!);

const end = Math.min(buf.length, start + len);
console.log(`文件偏移 0x${start.toString(16)} .. 0x${end.toString(16)}\n`);

let cur = start;
while (cur < end) {
  if (buf[cur]! >= 0x20 && buf[cur]! <= 0x7e) {
    let e = cur;
    while (e < end && buf[e]! >= 0x20 && buf[e]! <= 0x7e) e++;
    if (e - cur >= 3) {
      const rva = offsetToRva(info.sections, cur);
      console.log(`  [0x${cur.toString(16)}${rva !== null ? ` / RVA 0x${rva.toString(16)}` : ''}] ${JSON.stringify(buf.slice(cur, e).toString('latin1'))}`);
    }
    cur = e + 1;
  } else {
    cur++;
  }
}
