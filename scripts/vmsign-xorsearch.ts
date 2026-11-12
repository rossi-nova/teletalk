/**
 * 全量 XOR 密钥搜索：找能把某段字节还原成 "vmsign_config_fi" 的密钥
 *
 * 遍历 0x8D0000..0x900000（.rdata 主体），对每个位置用所有单字节 XOR 试。
 * 也试：明文以 UTF-16LE 存放（v\0m\0s\0...）
 */
import { readFileSync } from 'node:fs';
import { parsePE, rvaToOffset, offsetToRva } from '../tools/disasm/pe.js';

const { buf, info } = parsePE('C:/Program Files (x86)/DingDing/main/current_new/SecurityGuardSDK64.dll');
const rd = info.sections.find((s) => s.name === '.rdata')!;
const start = rd.rawPointer;
const end = rd.rawPointer + rd.rawSize;

const pt = Buffer.from('vmsign_config_fi');
console.log('搜索明文 "vmsign_config_fi"（单字节 XOR / ADD 变换）\n');

let found = 0;

// 1) 单字节 XOR
for (let k = 1; k < 256 && found < 10; k++) {
  for (let i = start; i + pt.length <= end; i++) {
    if ((buf[i]! ^ k) !== pt[0]) continue;
    let ok = true;
    for (let j = 1; j < pt.length; j++) {
      if ((buf[i + j]! ^ k) !== pt[j]) { ok = false; break; }
    }
    if (ok) {
      console.log(`  [XOR 0x${k.toString(16)}] @ file 0x${i.toString(16)} / RVA 0x${offsetToRva(info.sections, i)!.toString(16)}`);
      found++;
      break;
    }
  }
}

// 2) 单字节 ADD
for (let k = 1; k < 256 && found < 20; k++) {
  for (let i = start; i + pt.length <= end; i++) {
    if (((buf[i]! - k) & 0xff) !== pt[0]) continue;
    let ok = true;
    for (let j = 1; j < pt.length; j++) {
      if (((buf[i + j]! - k) & 0xff) !== pt[j]) { ok = false; break; }
    }
    if (ok) {
      console.log(`  [ADD 0x${k.toString(16)}] @ file 0x${i.toString(16)}`);
      found++;
      break;
    }
  }
}

// 3) UTF-16LE 明文
const pt16 = Buffer.alloc(pt.length * 2);
for (let i = 0; i < pt.length; i++) pt16[i * 2] = pt[i]!;
for (let i = start; i + pt16.length <= end; i++) {
  if (buf.compare(pt16, 0, pt16.length, i, i + pt16.length) === 0) {
    console.log(`  [UTF-16LE] @ file 0x${i.toString(16)}`);
    found++;
    break;
  }
}

if (!found) console.log('  未找到任何形式的明文');

// 4) 检查已知密文段的完整结构（起点 0x8DFDD0）
const segStart = rvaToOffset(info.sections, 0x8dfdc0)!;
console.log('\n=== 完整段结构（从 0x8DFDC0 起 0x90 字节）===');
for (let i = 0; i < 0x90; i += 16) {
  const chunk = buf.subarray(segStart + i, segStart + i + 16);
  console.log(`  +0x${i.toString(16).padStart(2, '0')} ${chunk.toString('hex').match(/../g).join(' ')}`);
}
