import { parsePE, rvaToOffset } from './pe.js';

const file = process.argv[2]!;
const { buf, info } = parsePE(file);
const peOff = buf.readUInt32LE(0x3c);
const coff = peOff + 4;
const optSize = buf.readUInt16LE(coff + 16);
const opt = coff + 20;
const is64 = buf.readUInt16LE(opt) === 0x20b;
const ddOff = opt + (is64 ? 112 : 96);
const expRva = buf.readUInt32LE(ddOff);
if (!expRva) { console.log('无导出表'); process.exit(0); }
const expOff = rvaToOffset(info.sections, expRva)!;
const nNames = buf.readUInt32LE(expOff + 24);
const namesRva = buf.readUInt32LE(expOff + 32);
const namesOff = rvaToOffset(info.sections, namesRva)!;
console.log(`导出函数 ${nNames} 个：`);
const names: string[] = [];
for (let i = 0; i < nNames; i++) {
  const rva = buf.readUInt32LE(namesOff + i * 4);
  const off = rvaToOffset(info.sections, rva)!;
  const end = buf.indexOf(0, off);
  names.push(buf.slice(off, end).toString('latin1'));
}
names.sort().forEach((n) => console.log('  ' + n));
