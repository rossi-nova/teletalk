/**
 * vmsign 配置解密尝试
 *
 * 目标：解出 0x8DFDC0 附近的加密配置
 * 已知明文可能含："vmsign_config_fi"、"sign"、JSON、URL 等
 */

const blocks = [
  { tag: '0x8DFDD0', hex: '19 b1 32 19 99 9c b2 98 96 19 98 18 b2 16 1a 9b 99 9c 16 31 1c 9c b0 96 18 9b 9c 9c 1b 1c 19 1a b2 9b 18 31' },
  { tag: '0x8DFE00', hex: '54 19 6c f8 9f 7b 1e 4e 04 2a ae 27 a8 e2 b6 8e 6b 7b d1 b2 ec 81 00 38 2c 6d' },
  { tag: '0x8DFE20', hex: '66 73 37 6c 27 21 65 7e 0d 60 7c 34 67 27 37 58 73 66 62 7d 66 65 60 34 6a 7c 86 00 3f 3f 78 69' },
  { tag: '0x8DFE50', hex: '29 bc ed 56 27 48 41 6e 9e fd 55 45 dd 1c f9 21 4f aa 42 ad 49 62' },
  { tag: '0x8DFE70', hex: 'bb b2 31 ba 37 39 1e b1 b7 37 36 1f 10 ba b7 37 10 b6 37 b7 33' },
  { tag: '0x8DFEA0', hex: '94 14 12 2f 17 95 95 9f ad 2e 3e ae 96 bd 3e 16 9d 9e 10' },
  { tag: '0x8DFEC0', hex: '37 17 57 30 10 50 4d 2d 6d 4e 2e 6e 4b 2b 6b 44 24 64 41 21 61 42 22 62 5f 3f 35 16 f6 36 13 f3 33 2c 0c 4c 29 09 49 2a 0a 4a 27 07 47 20 00 40 3d 1d 5d 3e e5 25 06 e6 26 03 e3 23 1c fc 5b d4' },
];

function toBuf(hex: string): Buffer {
  return Buffer.from(hex.replace(/\s/g, ''), 'hex');
}

function show(label: string, buf: Buffer) {
  const ascii = [...buf].map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.')).join('');
  const printable = [...buf].filter((b) => b >= 0x20 && b < 0x7f).length;
  console.log(`  ${label.padEnd(18)} | ${ascii}  (${printable}/${buf.length})`);
}

for (const { tag, hex } of blocks) {
  const buf = toBuf(hex);
  console.log(`\n=== ${tag} (${buf.length}B) ===`);
  show('原文', buf);

  // 尝试常见变换
  // 1) 单字节 XOR
  let bestXor = { k: -1, score: 0, out: Buffer.alloc(0) };
  for (let k = 1; k < 256; k++) {
    const out = Buffer.from(buf.map((b) => b ^ k));
    const score = [...out].filter((b) => (b >= 0x20 && b < 0x7f) || b === 0x0a).length;
    if (score > bestXor.score) bestXor = { k, score, out };
  }
  show(`XOR 0x${bestXor.k.toString(16)}`, bestXor.out);

  // 2) 单字节减法（凯撒）
  let bestSub = { k: -1, score: 0, out: Buffer.alloc(0) };
  for (let k = 1; k < 256; k++) {
    const out = Buffer.from(buf.map((b) => (b - k) & 0xff));
    const score = [...out].filter((b) => (b >= 0x20 && b < 0x7f) || b === 0x0a).length;
    if (score > bestSub.score) bestSub = { k, score, out };
  }
  show(`SUB 0x${bestSub.k.toString(16)}`, bestSub.out);

  // 3) 加法
  let bestAdd = { k: -1, score: 0, out: Buffer.alloc(0) };
  for (let k = 1; k < 256; k++) {
    const out = Buffer.from(buf.map((b) => (b + k) & 0xff));
    const score = [...out].filter((b) => (b >= 0x20 && b < 0x7f) || b === 0x0a).length;
    if (score > bestAdd.score) bestAdd = { k, score, out };
  }
  show(`ADD 0x${bestAdd.k.toString(16)}`, bestAdd.out);
}

console.log('\n\n=== 已知明文对照 ===');
console.log('若 0x8DFDD0 解密为 "vmsign_config_fi"，则密钥推导：');
const enc = toBuf(blocks[0]!.hex);
const plain = Buffer.from('vmsign_config_fi');
console.log('  密文[0..16]:', enc.subarray(0, 16).toString('hex'));
console.log('  明文       :', plain.toString('hex'));
const xorKeys = plain.map((p, i) => enc[i]! ^ p);
console.log('  XOR 密钥流:', xorKeys.map((k) => k.toString(16).padStart(2, '0')).join(' '));
const subKeys = plain.map((p, i) => (enc[i]! - p) & 0xff);
console.log('  SUB 密钥流:', subKeys.map((k) => k.toString(16).padStart(2, '0')).join(' '));
