/**
 * 假设 vmsign 配置是「字符打散存放」
 *
 * 明文 "vmsign_config_fi" 的字符码：
 *   v=0x76 m=0x6d s=0x73 i=0x69 g=0x67 n=0x6e _=0x5f
 *   c=0x63 o=0x6f f=0x66 t=0x74 i=0x69
 *
 * 检查整个 0x8DFDC0 区域是否散落这些字符（或其简单变换）。
 */
import { readFileSync } from 'node:fs';
import { parsePE, rvaToOffset } from '../tools/disasm/pe.js';

const { buf, info } = parsePE('C:/Program Files (x86)/DingDing/main/current_new/SecurityGuardSDK64.dll');
const start = rvaToOffset(info.sections, 0x8dfd80)!;
const region = buf.subarray(start, start + 0x400);

const needed = new Map<number, string>([
  [0x76, 'v'], [0x6d, 'm'], [0x73, 's'], [0x69, 'i'], [0x67, 'g'],
  [0x6e, 'n'], [0x5f, '_'], [0x63, 'c'], [0x6f, 'o'], [0x66, 'f'], [0x74, 't'],
]);

console.log('=== 在 0x8DFD80 区域搜索明文字符（直接值）===\n');
for (const [code, ch] of needed) {
  const hits: number[] = [];
  for (let i = 0; i < region.length; i++) if (region[i] === code) hits.push(i);
  console.log(`  '${ch}' (0x${code.toString(16)}): ${hits.length} 处 ${hits.slice(0, 5).map((h) => '0x' + h.toString(16)).join(' ')}`);
}

console.log('\n=== 搜索 XOR 0x80 后的值（高位翻转）===\n');
for (const [code, ch] of needed) {
  const x = code ^ 0x80;
  const hits: number[] = [];
  for (let i = 0; i < region.length; i++) if (region[i] === x) hits.push(i);
  if (hits.length) console.log(`  '${ch}'^0x80 (0x${x.toString(16)}): ${hits.length} 处`);
}

console.log('\n=== 对每个字节尝试：找能还原成 vmsign_config 的变换 ===\n');
// 这段密文：19 b1 32 19 99 9c b2 98 96 19 98 18 b2 16 1a 9b
const ct = region.subarray(0x40, 0x40 + 35); // 0x8DFDC0 相对 0x8DFD80 是 0x40
console.log('ct 起点相对 region = 0x40');
console.log('ct:', ct.subarray(0, 16).toString('hex').match(/../g).join(' '));

// 尝试：ct[i] 的某几位 = pt[i] 的某几位
const pt = Buffer.from('vmsign_config_fi');
console.log('\n位域分离分析：');
for (let i = 0; i < 8; i++) {
  console.log(`  [${i}] ct=0x${ct[i]!.toString(16).padStart(2, '0')} pt=0x${pt[i]!.toString(16).padStart(2, '0')}`);
  console.log(`      ct 高4=0x${(ct[i]! >> 4).toString(16)} 低4=0x${(ct[i]! & 15).toString(16)}`);
  console.log(`      pt 高4=0x${(pt[i]! >> 4).toString(16)} 低4=0x${(pt[i]! & 15).toString(16)}`);
}

console.log('\n=== 假设 ct = pt ^ (pt >> 3) 或类似 ===');
const transforms: Array<[string, (b: number) => number]> = [
  ['b ^ (b>>1)', (b) => b ^ (b >> 1)],
  ['b ^ (b<<1)&0xff', (b) => b ^ ((b << 1) & 0xff)],
  ['b*2&0xff', (b) => (b * 2) & 0xff],
  ['b*3&0xff', (b) => (b * 3) & 0xff],
  ['b+0x19', (b) => (b + 0x19) & 0xff],
  ['~(b)', (b) => (~b) & 0xff],
  ['rot4(b)', (b) => ((b << 4) | (b >> 4)) & 0xff],
];
for (const [name, fn] of transforms) {
  let match = 0;
  for (let i = 0; i < pt.length; i++) if (fn(pt[i]!) === ct[i]) match++;
  if (match > 0) console.log(`  ${name}: ${match}/${pt.length} 匹配`);
}
