/** 从 SDK 中提取字符串，判断内部是否有明文协议线索 */
import { parsePE } from './pe.js';

const { buf } = parsePE(process.argv[2]!);
const out: string[] = [];
let cur = '';
for (let i = 0; i < buf.length; i++) {
  const c = buf[i]!;
  if (c >= 0x20 && c < 0x7f) cur += String.fromCharCode(c);
  else {
    if (cur.length >= 6) out.push(cur);
    cur = '';
  }
}
console.log(`提取 ${out.length} 个字符串`);
const uniq = [...new Set(out)];

// 找签名/加密相关
const keys = /sign|token|umid|crypt|hash|sha|md5|aes|rsa|verify|key/i;
console.log('\n=== 签名相关 ===');
uniq.filter((s) => keys.test(s)).slice(0, 40).forEach((s) => console.log('  ' + s));

console.log('\n=== 错误信息 ===');
uniq.filter((s) => /error|fail|invalid|missing|unsupport/i.test(s)).slice(0, 20).forEach((s) => console.log('  ' + s));
