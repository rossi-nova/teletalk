/**
 * x5-sign 深度结构分析
 *
 * 已确认：
 *   前 12 字符固定 "wzMK2c002xAA"
 *   解码 66 字节 = [0..59] 正文 60B + [60..65] 尾部 6B（2 字节重复 3 次）
 *
 * 本脚本：
 *   1. 验证尾部 6 字节是否恒定模式
 *   2. 找正文里的长度/时间戳/版本字段
 *   3. 比对多个样本找变化区域
 */

const samples = [
  { tag: 'mem0', s: 'wzMK2c002xAAIUSpEi5MzgbF8qaUsUShTmNrh+l+9LptNeixSpH4QiUVnoOJGfbjDPjUv653/9Wn64ClF/tAxRPkpxFEsUShRLFEoU' },
  { tag: 'mem1', s: 'wzMK2c002xAAJt0tuz31IO8Rx2JtBt0m1+TyAHD5bT30snE20xZhxbySBwQQnm9klX9NODfwZlI+bBkijnzZQopjPpbdNt0m3TbdJt' },
  { tag: 'mem2', s: 'wzMK2c002xAAJ6QhWfVDACgPi38EF6QnruWLAQn4FDyNswg3qhcYxMWTfgVpnxZl7H40OU7xH1NHbWAj932gQ/NiR5ekN6QnpDekJ6' },
  { tag: 'cap',  s: 'wzMK2c002xAALVaBW9Hwl2Cjiij2nVaNXE95q/tS5pZ/GfqdWL3qbjc5jK+bNeTPHtTGk7xb7fm1x5KJBddS6QHItT1WnVaNVp1WjV' },
];

function decode(s: string): Buffer {
  return Buffer.from(s.replace(/[^A-Za-z0-9+/=]/g, ''), 'base64');
}

console.log('=== 深度结构分析 ===\n');
console.log('样本          前12字符        解码长度  尾6字节      尾2字节x3?');
for (const { tag, s } of samples) {
  const d = decode(s);
  const tail = d.subarray(d.length - 6);
  const isRepeat = tail[0] === tail[2] && tail[2] === tail[4] && tail[1] === tail[3] && tail[3] === tail[5];
  console.log(
    `${tag.padEnd(12)}  ${s.slice(0, 12)}  ${String(d.length).padStart(6)}    ${tail.toString('hex')}  ${isRepeat ? 'YES' : 'no'}`,
  );
}

console.log('\n=== 全 66 字节 hexdump ===\n');
for (const { tag, s } of samples) {
  const d = decode(s);
  console.log(`[${tag}]`);
  for (let i = 0; i < d.length; i += 16) {
    const chunk = d.subarray(i, Math.min(i + 16, d.length));
    const hex = [...chunk].map((b) => b.toString(16).padStart(2, '0')).join(' ');
    console.log(`  ${String(i).padStart(2)}: ${hex}`);
  }
  console.log('');
}

console.log('\n=== 逐字节变化统计（4 样本）===\n');
const decoded = samples.map((x) => decode(x.s));
const len = Math.min(...decoded.map((d) => d.length));
let vary = 0;
const varyPos: number[] = [];
for (let p = 0; p < len; p++) {
  const vals = new Set(decoded.map((d) => d[p]));
  if (vals.size > 1) { vary++; varyPos.push(p); }
}
console.log(`变化位置: ${vary}/${len}`);
console.log('变化位置列表:', varyPos.join(','));

// 分段统计
console.log('\n=== 分段（每 6 字节）变化率 ===');
for (let seg = 0; seg < len; seg += 6) {
  const inSeg = varyPos.filter((p) => p >= seg && p < seg + 6).length;
  console.log(`  [${String(seg).padStart(2)}..${String(seg + 5).padStart(2)}] 变化 ${inSeg}/6`);
}

// 前 12 字符对应解码前 9 字节（12 base64 字符 = 9 字节）
console.log('\n=== 前 12 base64 字符解码（9 字节）===');
const head9 = Buffer.from(samples[0]!.s.slice(0, 12), 'base64');
console.log('hex:', head9.toString('hex'));
console.log('ascii:', JSON.stringify(head9.toString('latin1')));
