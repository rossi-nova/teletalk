/**
 * 分析 SecurityGuardSDK64.dll 的导出函数签名
 * 通过反汇编函数入口的 prologue 推断参数个数
 */
import { parsePE, rvaToOffset } from './pe.js';

const file = process.argv[2]!;
const fnName = process.argv[3]!;
const { buf, info } = parsePE(file);

const peOff = buf.readUInt32LE(0x3c);
const coff = peOff + 4;
const optSize = buf.readUInt16LE(coff + 16);
const opt = coff + 20;
const is64 = buf.readUInt16LE(opt) === 0x20b;
const ddOff = opt + (is64 ? 112 : 96);
const expOff = rvaToOffset(info.sections, buf.readUInt32LE(ddOff))!;

const nNames = buf.readUInt32LE(expOff + 24);
const namesRva = buf.readUInt32LE(expOff + 32);
const ordRva = buf.readUInt32LE(expOff + 36);
const funcRva = buf.readUInt32LE(expOff + 28);
const namesOff = rvaToOffset(info.sections, namesRva)!;
const ordsOff = rvaToOffset(info.sections, ordRva)!;
const funcsOff = rvaToOffset(info.sections, funcRva)!;

for (let i = 0; i < nNames; i++) {
  const nrva = buf.readUInt32LE(namesOff + i * 4);
  const noff = rvaToOffset(info.sections, nrva)!;
  const end = buf.indexOf(0, noff);
  const name = buf.slice(noff, end).toString('latin1');
  if (name !== fnName) continue;

  const ord = buf.readUInt16LE(ordsOff + i * 2);
  const fRva = buf.readUInt32LE(funcsOff + ord * 4);
  const fOff = rvaToOffset(info.sections, fRva);
  if (fOff === null) { console.log('RVA 映射失败'); break; }

  console.log(`函数 ${name}`);
  console.log(`  RVA: 0x${fRva.toString(16)}  文件偏移: 0x${fOff.toString(16)}`);
  console.log(`  入口字节: ${buf.slice(fOff, fOff + 32).toString('hex')}`);
  console.log(`  Win64 参数寄存器: rcx, rdx, r8, r9`);
  break;
}
