/** 扫描所有 RIP 相对寻址（任意 opcode）指向目标 RVA */
import { parsePE } from './pe.js';

const [, , file, ...rvas] = process.argv;
const wanted = new Set(rvas.map((r) => parseInt(r, 16)));
const { buf, info } = parsePE(file!);
const text = info.sections.find((s) => s.name === '.text');
if (!text) { console.log('无 .text'); process.exit(1); }

const base = text.virtualAddress;
const len = text.rawSize;
const tOff = text.rawPointer;

// 通用扫描：任何指令里出现 disp32，且 next_ip + disp32 == 目标
// 启发式：modrm 的 mod=00 rm=101（RIP 相对）
for (let i = 0; i < len - 7; i++) {
  const b0 = buf[tOff + i]!;
  // 常见前缀
  if (b0 !== 0x48 && b0 !== 0x4c && b0 !== 0xff && b0 !== 0x8b && b0 !== 0x8d &&
      b0 !== 0x89 && b0 !== 0x0f && b0 !== 0x66 && b0 !== 0x83 && b0 !== 0x81) continue;
  // 尝试在 i+2 或 i+1 处找 modrm
  for (const mOff of [i + 2, i + 1, i + 3]) {
    const insnLen = (mOff - i) + 1 + 4;
    const modrm = buf[tOff + mOff]!;
    if ((modrm & 0xc7) !== 0x05) continue;
    const nextRva = base + i + insnLen;
    const disp = buf.readInt32LE(tOff + mOff + 1);
    const target = nextRva + disp;
    if (wanted.has(target)) {
      const bytes = buf.slice(tOff + i, tOff + i + insnLen).toString('hex');
      console.log(`  0x${(base + i).toString(16)}  [${bytes}] → 0x${target.toString(16)}`);
    }
    break;
  }
}
