/**
 * 扫描函数体内的「跳转表分发」指令：jmp/call [rsp+reg*8] / [rsp+rax+70h] 等
 * 用法: npx tsx tools/disasm/find-dispatch.ts <file> <rvaHex> [扫描字节数]
 */
import { Decoder, Formatter, FormatterSyntax, Mnemonic } from 'iced-x86';
import { parsePE, rvaToOffset } from './pe.js';

const [, , file, rvaHex, lenArg] = process.argv;
const start = parseInt(rvaHex!, 16);
const len = Number(lenArg ?? 0x6000);
const { buf, info } = parsePE(file!);
const fmt = new Formatter(FormatterSyntax.Nasm);

let cur = start;
const end = start + len;
let hits = 0;

while (cur < end) {
  const off = rvaToOffset(info.sections, cur);
  if (off === null) break;
  const dec = new Decoder(64, buf.slice(off, off + 16), 0);
  dec.ip = BigInt(cur);
  const ins = dec.decode();
  if (ins.code === 0) { cur += 1; continue; }
  const text = fmt.format(ins);
  cur += ins.length;

  if (ins.mnemonic === Mnemonic.Jmp || ins.mnemonic === Mnemonic.Call) {
    if (/\[(rsp|rbp)/.test(text) && /(\*\d|rax|rcx|rdx|rbx|rsi|rdi|r8|r9)/.test(text)) {
      console.log(`  0x${ins.ip.toString(16)}  ${text}`);
      hits++;
    }
  }
}
console.log(`\n共 ${hits} 处内存间接跳转`);
