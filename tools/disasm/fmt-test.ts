import { Decoder, Formatter, FormatterSyntax } from 'iced-x86';
import { parsePE, rvaToOffset } from './pe.js';
const { buf, info } = parsePE('C:/Program Files (x86)/DingDing/main/current_new/SecurityGuardSDK64.dll');
const fmt = new Formatter(FormatterSyntax.Nasm);
let cur = 0x182380;
for (let i = 0; i < 20; i++) {
  const off = rvaToOffset(info.sections, cur)!;
  const d = new Decoder(64, buf.slice(off, off + 16), 0);
  d.ip = BigInt(cur);
  const ins = d.decode();
  console.log(cur.toString(16), '|', JSON.stringify(fmt.format(ins)));
  cur += ins.length;
}
