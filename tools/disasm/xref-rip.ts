/** 扫描 RIP 相对引用：48 8B 05/0D/15/1D (mov) 与 FF 15 (call) 指向目标 RVA */
import { readFileSync } from 'node:fs';
import { parsePE, rvaToOffset, offsetToRva } from './pe.js';

const [, , file, ...rvas] = process.argv;
const wanted = new Set(rvas.map((r) => parseInt(r, 16)));
const { buf, info } = parsePE(file!);
const text = info.sections.find((s) => s.name === '.text');
if (!text) { console.log('无 .text'); process.exit(1); }

const base = text.virtualAddress;
const len = text.rawSize;
const tOff = text.rawPointer;

for (let i = 0; i < len - 7; i++) {
  const b0 = buf[tOff + i]!;
  const b1 = buf[tOff + i + 1]!;
  const b2 = buf[tOff + i + 2]!;
  let isRip = false;
  let kind = '';
  if ((b0 === 0x48 || b0 === 0x4c) && (b1 === 0x8b || b1 === 0x89) && (b2 & 0xc7) === 0x05) { isRip = true; kind = b1 === 0x8b ? 'mov r,' : 'mov r,'; }
  else if (b0 === 0xff && b2 === 0x15 && (buf[tOff + i + 1]! & 0xc7) === 0x05) { }
  else if (b0 === 0xff && (buf[tOff + i + 1]! & 0xc7) === 0x05) { isRip = true; kind = 'call'; }
  if (!isRip) continue;
  const nextRva = base + i + 7;
  const disp = buf.readInt32LE(tOff + i + 3);
  const target = nextRva + disp;
  if (wanted.has(target)) {
    console.log(`  0x${(base + i).toString(16)}  ${kind} → 0x${target.toString(16)}`);
  }
}
