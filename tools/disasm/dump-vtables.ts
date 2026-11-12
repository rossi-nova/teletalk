/** dump SDK 中两个接口的虚表槽位 */
import { readFileSync } from 'node:fs';
import { parsePE, rvaToOffset } from './pe.js';

const { buf, info } = parsePE('C:/Program Files (x86)/DingDing/main/current_new/SecurityGuardSDK64.dll');
const IMAGE_BASE = 0x180000000;

function dumpVtable(name: string, vtblRva: number, n: number) {
  console.log(`\n== ${name} 虚表 @ RVA 0x${vtblRva.toString(16)} ==`);
  const off = rvaToOffset(info.sections, vtblRva)!;
  for (let i = 0; i < n; i++) {
    const va = buf.readBigUInt64LE(off + i * 8);
    const rva = Number(va - BigInt(IMAGE_BASE));
    if (rva < 0x1000 || rva > 0xab0000) { // 出了 .text 范围就停
      console.log(`  [${i}] 0x${i * 8}  -> 0x${va.toString(16)} （越界，截断）`);
      break;
    }
    console.log(`  [${i}] +0x${(i * 8).toString(16).padStart(2, '0')}  -> RVA 0x${rva.toString(16)}`);
  }
}

dumpVtable('ITrafficFilter', 0x8e1438, 24);

// ISecurityFactor 单例：.data 0xa29710 处的 qword 是虚表指针
const sfOff = rvaToOffset(info.sections, 0xa29710)!;
const sfVt = buf.readBigUInt64LE(sfOff);
console.log(`\nISecurityFactor 单例 @ 0xa29710，vtbl VA = 0x${sfVt.toString(16)} (RVA 0x${Number(sfVt - BigInt(IMAGE_BASE)).toString(16)})`);
dumpVtable('ISecurityFactor', Number(sfVt - BigInt(IMAGE_BASE)), 24);
