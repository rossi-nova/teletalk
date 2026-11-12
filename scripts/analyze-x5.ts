/**
 * 分析真实 x5-sign 的结构
 *
 * 已知三个样本（从钉钉进程内存提取）：
 *   wzMK2c002xAAIUSpEi5MzgbF8qaUsUShTmNrh+l+9LptNeixSpH4QiUVnoOJGfbjDPjUv653/9Wn64ClF/tAxRPkpxFEsUShRLFEoU
 *   wzMK2c002xAAJt0tuz31IO8Rx2JtBt0m1+TyAHD5bT30snE20xZhxbySBwQQnm9klX9NODfwZlI+bBkijnzZQopjPpbdNt0m3TbdJt
 *   wzMK2c002xAAJ6QhWfVDACgPi38EF6QnruWLAQn4FDyNswg3qhcYxMWTfgVpnxZl7H40OU7xH1NHbWAj932gQ/NiR5ekN6QnpDekJ6
 */

const samples = [
  'wzMK2c002xAAIUSpEi5MzgbF8qaUsUShTmNrh+l+9LptNeixSpH4QiUVnoOJGfbjDPjUv653/9Wn64ClF/tAxRPkpxFEsUShRLFEoU',
  'wzMK2c002xAAJt0tuz31IO8Rx2JtBt0m1+TyAHD5bT30snE20xZhxbySBwQQnm9klX9NODfwZlI+bBkijnzZQopjPpbdNt0m3TbdJt',
  'wzMK2c002xAAJ6QhWfVDACgPi38EF6QnruWLAQn4FDyNswg3qhcYxMWTfgVpnxZl7H40OU7xH1NHbWAj932gQ/NiR5ekN6QnpDekJ6',
];

// 抓包里的旧样本（对比）
const captured =
  'wzMK2c002xAALVaBW9Hwl2Cjiij2nVaNXE95q/tS5pZ/GfqdWL3qbjc5jK+bNeTPHtTGk7xb7fm1x5KJBddS6QHItT1WnVaNVp1WjV';

const all = [...samples, captured];

function b64decode(s: string): Buffer {
  // 宽松 base64：非标准字符按 0 处理
  const norm = s.replace(/[^A-Za-z0-9+/=]/g, '');
  return Buffer.from(norm, 'base64');
}

console.log('=== x5-sign 结构分析 ===\n');

for (const [i, s] of all.entries()) {
  const tag = i === all.length - 1 ? '抓包(旧)' : `内存[${i}]`;
  console.log(`--- ${tag} len=${s.length} ---`);
  console.log(`  原文: ${s}`);

  // 前缀 14 字符是 ASCII 明文
  const prefix = s.slice(0, 14);
  console.log(`  前缀(14): "${prefix}"`);
  console.log(`    wz = 魔数 | MK2c = 版本 | 002 = ? | x + 2 字符 = ?`);

  const rest = s.slice(14);
  console.log(`  主体 len=${rest.length}: ${rest}`);

  const bodyLen = rest.length;
  console.log(`  主体长度 % 4 = ${bodyLen % 4}`);

  const dec = b64decode(rest);
  console.log(`  解码(len=${dec.length}): ${dec.toString('hex')}`);
  console.log(`  解码 ascii: ${JSON.stringify(dec.toString('latin1').replace(/[^\x20-\x7e]/g, '.'))}`);
  console.log('');
}

console.log('\n=== 共性提取 ===');
const prefixes = all.map((s) => s.slice(0, 14));
console.log('所有前缀相同:', prefixes.every((p) => p === prefixes[0]));
console.log('前缀 =', prefixes[0]);

// 找相同位置
const minLen = Math.min(...all.map((s) => s.length));
console.log(`\n最小长度 ${minLen}，逐位比较：`);
let sameCount = 0;
const samePos: number[] = [];
for (let p = 0; p < minLen; p++) {
  const chars = new Set(all.map((s) => s[p]));
  if (chars.size === 1) { sameCount++; samePos.push(p); }
}
console.log(`相同位置 ${sameCount}/${minLen}`);
console.log('相同位置:', samePos.slice(0, 40).join(','), samePos.length > 40 ? '...' : '');

// 尾部特征
console.log('\n=== 尾部 20 字符 ===');
for (const [i, s] of all.entries()) {
  console.log(`  [${i}] ${s.slice(-20)}`);
}
