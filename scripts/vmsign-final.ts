/**
 * vmsign 配置解码器（修正版）
 *
 * 从汇编精确还原：
 *   107290  mov bl, 19h            ← bl = 0x19
 *   107292  mov eax, 2             ← rax 从 2 开始
 *   1072B0  shr bl, 7              ← bl = 0x19 >> 7 = 0
 *   1072B3  movzx edx, [rax+rdi-1] ← edx = ct[i-1]
 *   1072B8  mov ecx, edx
 *   1072BA  add cl, cl             ← cl = ct[i-1] * 2
 *   1072BC  or  cl, bl             ← cl |= 0（第一次）
 *   1072BE  mov [rax+rsi-1], cl    ← out[i-1] = cl
 *
 *   1072C2  movzx ecx, [rax+rdi]   ← ecx = ct[i]
 *   1072C6  shr dl, 7              ← dl = ct[i-1] >> 7（注意 dl 是 edx 低8位）
 *   1072CB  add cl, cl             ← cl = ct[i] * 2
 *   1072CD  or  cl, dl             ← cl |= ct[i-1]>>7
 *   1072CF  mov [rax+rsi], cl      ← out[i] = cl
 *
 *   add rax, 2; cmp eax, 26h
 *
 * 关键：bl 在循环开始时 = 上一轮的 ct[i-1]（mov ebx,ecx 在 1072C9），
 *       所以 shr bl,7 取的是 ct[i-1] 的最高位。
 *
 * 等价公式：
 *   out[i] = (ct[i] << 1) | (ct[i-1] >> 7)
 *   边界：out[0] = 0x33（预置常量，不参与计算）
 */
import { readFileSync } from 'node:fs';
import { parsePE, rvaToOffset } from '../tools/disasm/pe.js';

const { buf, info } = parsePE('C:/Program Files (x86)/DingDing/main/current_new/SecurityGuardSDK64.dll');

function decodeAt(rva: number, n: number): Buffer {
  const src = rvaToOffset(info.sections, rva)!;
  const ct = buf.subarray(src, src + n + 1);
  const out = Buffer.alloc(n);
  out[0] = 0x33;
  for (let i = 1; i < n; i++) {
    out[i] = (((ct[i]! << 1) & 0xff) | ((ct[i - 1]! >> 7) & 1)) & 0xff;
  }
  return out;
}

console.log('=== 段1: RVA 0x8DFDD0（79 字节）===\n');
const d1 = decodeAt(0x8dfdd0, 79);
console.log('hex:', d1.toString('hex').match(/../g).join(' '));
console.log('ascii:', JSON.stringify(d1.toString('latin1').replace(/[^\x20-\x7e]/g, '.')));
console.log('');

console.log('=== 段2: 尝试 RVA 0x8DFE20 ===\n');
const d2 = decodeAt(0x8dfe20, 56);
console.log('hex:', d2.toString('hex').match(/../g).join(' '));
console.log('ascii:', JSON.stringify(d2.toString('latin1').replace(/[^\x20-\x7e]/g, '.')));

console.log('\n=== 段3: 尝试 RVA 0x8DFE50 ===\n');
const d3 = decodeAt(0x8dfe50, 40);
console.log('ascii:', JSON.stringify(d3.toString('latin1').replace(/[^\x20-\x7e]/g, '.')));

console.log('\n=== 段4: RVA 0x8DFE70 ===\n');
const d4 = decodeAt(0x8dfe70, 32);
console.log('ascii:', JSON.stringify(d4.toString('latin1').replace(/[^\x20-\x7e]/g, '.')));

console.log('\n=== 段5: RVA 0x8DFEA0 ===\n');
const d5 = decodeAt(0x8dfea0, 32);
console.log('ascii:', JSON.stringify(d5.toString('latin1').replace(/[^\x20-\x7e]/g, '.')));

console.log('\n=== 段6: RVA 0x8DFEC0 ===\n');
const d6 = decodeAt(0x8dfec0, 64);
console.log('ascii:', JSON.stringify(d6.toString('latin1').replace(/[^\x20-\x7e]/g, '.')));

console.log('\n=== 注意 ===');
console.log('汇编里目标缓冲区是 [0A2A281h]，长度 0x26-2 = 36 字节。');
console.log('因此只有前 36 字节被解码，后面的是其它数据。');
console.log('\n段1 前 36 字节:');
console.log(JSON.stringify(d1.subarray(0, 36).toString('latin1')));
