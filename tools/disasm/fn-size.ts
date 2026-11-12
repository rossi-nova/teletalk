/**
 * 估算函数规模：从入口线性扫描到 ret 或下一函数边界
 * 用于给虚表方法定性（大函数 = 签名主体）
 */
import { Decoder, Formatter, FormatterSyntax, Mnemonic } from 'iced-x86';
import { parsePE, rvaToOffset } from './pe.js';

const [, , file, ...rvas] = process.argv;
const { buf, info } = parsePE(file!);
const fmt = new Formatter(FormatterSyntax.Nasm);

for (const hex of rvas) {
  const start = parseInt(hex!, 16);
  let cur = start;
  let insns = 0;
  let calls = 0;
  const callTargets = new Set<string>();
  let end = start;

  while (insns < 20000) {
    const off = rvaToOffset(info.sections, cur);
    if (off === null) break;
    const dec = new Decoder(64, buf.slice(off, off + 16), 0);
    dec.ip = BigInt(cur);
    const ins = dec.decode();
    if (ins.code === 0) break;
    insns++;
    cur += ins.length;
    end = cur;

    if (ins.mnemonic === Mnemonic.Call) {
      calls++;
      const t = fmt.format(ins);
      const m = t.match(/call ([0-9A-F]+)$/);
      if (m) callTargets.add(m[1]!);
      else callTargets.add(t.replace(/^call /, ''));
    }
    // ret 之后若紧跟 int3/对齐，视为函数结束
    if (ins.mnemonic === Mnemonic.Ret) {
      const nOff = rvaToOffset(info.sections, cur);
      if (nOff !== null) {
        const nb = buf[nOff]!;
        if (nb === 0xcc || nb === 0xc3 || nb === 0x90 || nb === 0x00) break;
      }
    }
  }

  console.log(`0x${start.toString(16)}: ${insns} 条指令, ${calls} 次调用, 跨度 0x${(end - start).toString(16)} 字节`);
  console.log(`   调用目标: ${[...callTargets].slice(0, 24).join(', ')}`);
}
