/** 列出文件中所有匹配关键字的偏移与上下文 */
import { readFileSync } from 'node:fs';
const [, , file, ...kws] = process.argv;
const buf = readFileSync(file!);
const s = buf.toString('latin1');
for (const kw of kws) {
  let i = -1;
  while ((i = s.indexOf(kw, i + 1)) >= 0) {
    // 找到一个可打印串的起点
    let a = i;
    while (a > 0 && s.charCodeAt(a - 1) >= 0x20 && s.charCodeAt(a - 1) <= 0x7e) a--;
    let b = i;
    while (b < s.length && s.charCodeAt(b) >= 0x20 && s.charCodeAt(b) <= 0x7e) b++;
    const before = buf.slice(Math.max(0, a - 24), a).toString('hex').replace(/(..)/g, '$1 ');
    const after = buf.slice(b, b + 24).toString('hex').replace(/(..)/g, '$1 ');
    console.log(`${kw} @ 0x${i.toString(16)}`);
    console.log(`   str: ${JSON.stringify(s.slice(a, b).slice(0, 140))}`);
    console.log(`   pre: ${before}`);
    console.log(`   post: ${after}`);
  }
}
