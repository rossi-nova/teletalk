/**
 * vmsign 配置编码分析（精确版）
 *
 * 结构假设：
 *   [len:4][pad:12][data:len]  重复
 *
 * 第一段：len=0x4F, data 从 +0x10 开始
 * 已知 data 前 35 字节对应 "vmsign_config_fi" 的加噪版
 */
import { readFileSync } from 'node:fs';
import { parsePE, rvaToOffset } from '../tools/disasm/pe.js';

const { buf } = parsePE('C:/Program Files (x86)/DingDing/main/current_new/SecurityGuardSDK64.dll');
const base = rvaToOffset(parsePE('C:/Program Files (x86)/DingDing/main/current_new/SecurityGuardSDK64.dll').info.sections, 0x8dfdc0)!;
const region = buf.subarray(base, base + 0x200);

console.log('=== 分段解析 ===\n');

// 尝试按 [len][pad][data] 切
let p = 0;
for (let seg = 0; seg < 8 && p + 16 < region.length; seg++) {
  const len = region.readUInt32LE(p);
  if (len === 0 || len > 0x200) { console.log(`@0x${p.toString(16)}: len=${len} 不合理，停止`); break; }
  const data = region.subarray(p + 16, p + 16 + len);
  console.log(`段 ${seg}: @0x${p.toString(16).padStart(3, '0')}  len=${len}(0x${len.toString(16)})`);
  console.log(`  data: ${data.subarray(0, 64).toString('hex').match(/../g).join(' ')}`);
  console.log(`  ascii: ${JSON.stringify(data.subarray(0, 64).toString('latin1').replace(/[^\x20-\x7e]/g, '.'))}`);
  p += 16 + len;
  // 对齐到 8
  p = (p + 7) & ~7;
  console.log('');
}

console.log('\n=== 第一段与 "vmsign_config_fi" 逐字节对照 ===\n');
const seg0 = region.subarray(0x10, 0x10 + 35);
const plain = 'vmsign_config_fi';
for (let i = 0; i < plain.length; i++) {
  const e = seg0[i]!;
  const pch = plain.charCodeAt(i);
  console.log(
    `  [${String(i).padStart(2)}] '${plain[i]}'(0x${pch.toString(16)})  ←  密文 0x${e.toString(16)}  XOR=0x${(e ^ pch).toString(16)}  SUB=0x${((e - pch) & 0xff).toString(16)}`,
  );
}

console.log('\n=== 剩余密文（0x33 起，18 字节）===');
const rest = seg0.subarray(plain.length);
console.log(`  hex: ${rest.toString('hex').match(/../g).join(' ')}`);
console.log(`  尝试 SUB 0x? 使结果可打印:`);
for (let k = 0; k < 256; k++) {
  const out = Buffer.from(rest.map((b) => (b - k) & 0xff));
  const pr = [...out].filter((b) => b >= 0x20 && b < 0x7f).length;
  if (pr >= rest.length - 2) {
    console.log(`    SUB 0x${k.toString(16)}: ${JSON.stringify(out.toString('latin1'))}`);
  }
}
