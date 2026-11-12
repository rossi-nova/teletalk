/**
 * vmsign 第一段密文的位级分析
 *
 * 观察：密文高位多为 0x1 或 0x9（即 bit7 翻转模式）
 *       0x19, 0xb1, 0x32, 0x99, 0x9c, 0xb2, 0x98, 0x96, 0x18, 0x16, 0x1a ...
 *
 * 假设：每组字节共享某个 bit 模式（编译器生成的 XOR 常量）
 */

const ct = Buffer.from(
  '19 b1 32 19 99 9c b2 98 96 19 98 18 b2 16 1a 9b 99 9c 16 31 1c 9c b0 96 18 9b 9c 9c 1b 1c 19 1a b2 9b 18 31'.replace(/\s/g, ''),
  'hex',
);
const pt = Buffer.from('vmsign_config_fi');

console.log('=== 密文位模式 ===\n');
console.log('idx  ct    二进   pt    pt二进  XOR');
for (let i = 0; i < pt.length; i++) {
  const c = ct[i]!;
  const p = pt[i]!;
  console.log(
    `${String(i).padStart(3)}  0x${c.toString(16).padStart(2, '0')} ${c.toString(2).padStart(8, '0')}  ` +
    `0x${p.toString(16).padStart(2, '0')} ${p.toString(2).padStart(8, '0')}  0x${(c ^ p).toString(16).padStart(2, '0')}`,
  );
}

console.log('\n=== 密钥流（XOR）位模式 ===');
const ks = [...pt].map((p, i) => ct[i]! ^ p);
console.log(ks.map((k) => k.toString(16).padStart(2, '0')).join(' '));
console.log(ks.map((k) => k.toString(2).padStart(8, '0')).join('\n'));

console.log('\n=== 检查：密钥流是否 = 位置 i 的函数 ===');
for (let i = 0; i < ks.length; i++) {
  console.log(`  i=${String(i).padStart(2)}  ks=0x${ks[i]!.toString(16).padStart(2, '0')}  (i<<4)&0xff=0x${((i << 4) & 0xff).toString(16).padStart(2, '0')}  i*17&0xff=0x${((i * 17) & 0xff).toString(16).padStart(2, '0')}`);
}

console.log('\n=== 假设：密文 = 明文 XOR 某个固定字节序列 ===');
console.log('密钥流:', ks.map((k) => k.toString(16).padStart(2, '0')).join(''));
console.log('若这是 repeating key，找周期:');
for (const period of [2, 3, 4, 5, 6, 8]) {
  let ok = true;
  for (let i = 0; i < ks.length; i++) {
    if (i >= period && ks[i] !== ks[i - period]) { ok = false; break; }
  }
  if (ok) console.log(`  周期 ${period} 匹配！key = ${ks.slice(0, period).map((k) => k.toString(16)).join(' ')}`);
}

console.log('\n=== 假设：密文 = (明文 + i*C) & 0xff ===');
for (let C = 0; C < 256; C++) {
  let ok = true;
  for (let i = 1; i < pt.length; i++) {
    const expected = (pt[i]! + i * C) & 0xff;
    if (expected !== ct[i]!) { ok = false; break; }
  }
  if (ok) console.log(`  匹配 C=0x${C.toString(16)}`);
}

console.log('\n=== 假设：密文[i] = f(明文[i]) 单表替换 ===');
const map = new Map<number, Set<number>>();
for (let i = 0; i < pt.length; i++) {
  const p = pt[i]!;
  if (!map.has(p)) map.set(p, new Set());
  map.get(p)!.add(ct[i]!);
}
for (const [p, cs] of map) {
  console.log(`  明文 0x${p.toString(16)}('${String.fromCharCode(p)}') → 密文 {${[...cs].map((c) => c.toString(16)).join(', ')}} ${cs.size > 1 ? '（多值，非单表）' : ''}`);
}
