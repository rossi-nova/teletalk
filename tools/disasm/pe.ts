/**
 * 极简 PE 解析：提取节表，把 RVA 映射到文件偏移
 * 用于在 DLL 中定位字符串与代码段
 */
import { readFileSync } from 'node:fs';

export interface Section {
  name: string;
  virtualAddress: number;
  virtualSize: number;
  rawPointer: number;
  rawSize: number;
}

export interface PEInfo {
  sections: Section[];
  imageBase: bigint;
  is64: boolean;
}

export function parsePE(file: string): { info: PEInfo; buf: Buffer } {
  const buf = readFileSync(file);

  if (buf.readUInt16LE(0) !== 0x5a4d) throw new Error('不是 PE 文件（缺少 MZ）');
  const peOffset = buf.readUInt32LE(0x3c);
  if (buf.readUInt32LE(peOffset) !== 0x00004550) throw new Error('缺少 PE 签名');

  const coff = peOffset + 4;
  const numSections = buf.readUInt16LE(coff + 2);
  const optSize = buf.readUInt16LE(coff + 16);

  const opt = coff + 20;
  const magic = buf.readUInt16LE(opt);
  const is64 = magic === 0x20b;
  const imageBase = is64 ? buf.readBigUInt64LE(opt + 24) : BigInt(buf.readUInt32LE(opt + 28));

  const sections: Section[] = [];
  const secStart = opt + optSize;
  for (let i = 0; i < numSections; i++) {
    const s = secStart + i * 40;
    const name = buf.slice(s, s + 8).toString('latin1').replace(/\0+$/, '');
    sections.push({
      name,
      virtualSize: buf.readUInt32LE(s + 8),
      virtualAddress: buf.readUInt32LE(s + 12),
      rawSize: buf.readUInt32LE(s + 16),
      rawPointer: buf.readUInt32LE(s + 20),
    });
  }

  return { info: { sections, imageBase, is64 }, buf };
}

/** RVA → 文件偏移 */
export function rvaToOffset(sections: Section[], rva: number): number | null {
  for (const s of sections) {
    if (rva >= s.virtualAddress && rva < s.virtualAddress + Math.max(s.virtualSize, s.rawSize)) {
      return s.rawPointer + (rva - s.virtualAddress);
    }
  }
  return null;
}

/** 文件偏移 → RVA */
export function offsetToRva(sections: Section[], off: number): number | null {
  for (const s of sections) {
    if (off >= s.rawPointer && off < s.rawPointer + s.rawSize) {
      return s.virtualAddress + (off - s.rawPointer);
    }
  }
  return null;
}

// CLI
if (process.argv[2] && process.argv[1]?.endsWith('pe.ts')) {
  const { info, buf } = parsePE(process.argv[2]);
  console.log(`文件 ${buf.length} 字节，${info.is64 ? '64' : '32'} 位，ImageBase=0x${info.imageBase.toString(16)}`);
  console.log('\n节表：');
  console.log('  名称        虚拟地址    虚拟大小      文件偏移    文件大小');
  for (const s of info.sections) {
    console.log(
      `  ${s.name.padEnd(10)} 0x${s.virtualAddress.toString(16).padStart(8, '0')}  ` +
      `0x${s.virtualSize.toString(16).padStart(8, '0')}  0x${s.rawPointer.toString(16).padStart(8, '0')}  ` +
      `0x${s.rawSize.toString(16).padStart(8, '0')}`,
    );
  }
}
