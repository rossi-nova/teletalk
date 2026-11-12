/** 读取 PE 中任意 RVA 的字节（hex + ascii） */
import { parsePE, rvaToOffset } from './pe.js';

const [, , file, rvaHex, lenArg] = process.argv;
const rva = parseInt(rvaHex!, 16);
const len = Number(lenArg ?? 32);
const { buf, info } = parsePE(file!);
const off = rvaToOffset(info.sections, rva);
if (off === null) { console.log('RVA 无法映射'); process.exit(1); }
const slice = buf.slice(off, off + len);
console.log(`RVA 0x${rva.toString(16)} (file 0x${off.toString(16)}):`);
console.log('  hex: ' + slice.toString('hex').replace(/(..)/g, '$1 '));
console.log('  ascii: ' + JSON.stringify(slice.toString('latin1').replace(/[^\x20-\x7e]/g, '·')));
