/** 反汇编函数入口若干字节 */
import { parsePE, rvaToOffset } from './pe.js';

const [file, rvaHex, countArg] = process.argv.slice(2);
const { buf, info } = parsePE(file!);
const rva = parseInt(rvaHex!, 16);
const off = rvaToOffset(info.sections, rva);
if (off === null) { console.log('RVA 无效'); process.exit(1); }

const n = Number(countArg ?? 160);
const bytes = buf.slice(off, off + n);

// 极简 x86-64 反汇编：只识别常见指令
const REG64 = ['rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi','r8','r9','r10','r11','r12','r13','r14','r15'];
let p = 0;
const out: string[] = [];
while (p < bytes.length) {
  const start = p;
  const b = bytes[p]!;
  let text = '';

  // push r64: 50-57, 41 50-57
  if (b >= 0x50 && b <= 0x57) { text = `push ${REG64[b - 0x50]}`; p += 1; }
  else if (b === 0x41 && bytes[p+1] !== undefined && bytes[p+1]! >= 0x50 && bytes[p+1]! <= 0x57) {
    text = `push ${REG64[8 + bytes[p+1]! - 0x50]}`; p += 2;
  }
  // sub rsp, imm
  else if (b === 0x48 && bytes[p+1] === 0x81 && bytes[p+2] === 0xec) {
    const imm = bytes.readUInt32LE(p+3);
    text = `sub rsp, 0x${imm.toString(16)}`; p += 7;
  }
  // mov rax, [rip+disp32]
  else if (b === 0x48 && bytes[p+1] === 0x8b && bytes[p+2] === 0x05) {
    const disp = bytes.readInt32LE(p+3);
    text = `mov rax, [rip+0x${disp.toString(16)}]`; p += 7;
  }
  // xor eax, eax
  else if (b === 0x31 && bytes[p+1] === 0xc0) { text = 'xor eax, eax'; p += 2; }
  // ret
  else if (b === 0xc3) { text = 'ret'; p += 1; }
  // nop
  else if (b === 0x90) { text = 'nop'; p += 1; }
  else { text = `db 0x${b.toString(16).padStart(2,'0')}`; p += 1; }

  out.push(`  +${String(start).padStart(3)}  ${bytes.slice(start, p).toString('hex').padEnd(24)} ${text}`);
  if (p - start > 8) break;
}
console.log(`函数 @0x${rva.toString(16)}:`);
console.log(out.join('\n'));
