/**
 * 修正版 RTTI 解析（x64：COL 用 32 位相对偏移指向 TypeDescriptor）
 *
 * x64 CompleteObjectLocator:
 *   +0x00 signature (1 for x64)
 *   +0x04 offset
 *   +0x08 cdOffset
 *   +0x0C pTypeDescriptor (RVA, 4 字节)
 *   +0x10 pClassHierarchyDescriptor (RVA, 4 字节)
 *   +0x14 pSelf (RVA, 4 字节)  ← x64 特有
 */
import { parsePE, rvaToOffset } from './pe.js';

const [, , file, ...nameFilters] = process.argv;
const { buf, info } = parsePE(file!);
const IMAGE_BASE = 0x180000000n;

const rva2off = (rva: number) => rvaToOffset(info.sections, rva);

/* 1) 找 TypeDescriptor 字符串的真实 RVA */
const whole = buf.toString('latin1');
const found: Array<{ name: string; rva: number }> = [];
const re = /\.\?A[VU]([A-Za-z0-9_@?$]{2,80})@@/g;
let m: RegExpExecArray | null;
while ((m = re.exec(whole)) !== null) {
  for (const s of info.sections) {
    if (m.index >= s.rawPointer && m.index < s.rawPointer + s.rawSize) {
      found.push({ name: m[0], rva: s.virtualAddress + (m.index - s.rawPointer) });
      break;
    }
  }
}

const wanted = found.filter((f) =>
  nameFilters.length
    ? nameFilters.some((n) => f.name.toLowerCase().includes(n.toLowerCase()))
    : /Sign|Token|Encrypt|AliStore|Security|Traffic|Static|Factor|VM/i.test(f.name),
);

console.log(`TypeDescriptor 总数 ${found.length}，筛选后 ${wanted.length}\n`);

/* 2) 在 .rdata 中找 COL（pTypeDescriptor == td.rva） */
const rd = info.sections.find((s) => s.name === '.rdata')!;
const colHits = new Map<number, number[]>();   // colRva -> [tdRva]
for (let off = rd.rawPointer; off + 24 <= rd.rawPointer + rd.rawSize; off += 4) {
  const typ = buf.readUInt32LE(off + 12);
  const hit = wanted.find((w) => w.rva === typ);
  if (!hit) continue;
  const sig = buf.readUInt32LE(off);
  if (sig !== 0 && sig !== 1) continue;
  const self = buf.readUInt32LE(off + 20);
  const colRva = rd.virtualAddress + (off - rd.rawPointer);
  // x64 下 pSelf 应该等于 colRva
  if (self !== colRva) continue;
  const arr = colHits.get(colRva) ?? [];
  arr.push(typ);
  colHits.set(colRva, arr);
}

console.log(`找到 ${colHits.size} 个 COL（自校验通过）\n`);

/* 3) 找虚表：qword[-1] == IMAGE_BASE + colRva */
const vtbls = new Map<number, number>();   // vtblRva -> colRva
for (const sec of info.sections.filter((s) => s.name === '.rdata' || s.name === '.data')) {
  for (let off = sec.rawPointer + 8; off + 8 <= sec.rawPointer + sec.rawSize; off += 8) {
    const v = buf.readBigUInt64LE(off);
    const expect = IMAGE_BASE + BigInt((v - 0n) & 0n);  // 占位
    const rv = Number(v - IMAGE_BASE);
    if (!colHits.has(rv)) continue;
    const vtblRva = sec.virtualAddress + (off - sec.rawPointer) + 8;
    vtbls.set(vtblRva, rv);
  }
}

console.log(`找到 ${vtbls.size} 个虚表\n`);

/* 4) 输出 */
for (const [vtRva, colRva] of [...vtbls].sort((a, b) => a[0] - b[0])) {
  const tds = colHits.get(colRva)!;
  const td = found.find((f) => f.rva === tds[0]);
  if (!td) continue;
  if (!wanted.some((w) => w.rva === td.rva)) continue;

  const off = rva2off(vtRva);
  if (off === null) continue;
  const fns: number[] = [];
  for (let i = 0; i < 10; i++) {
    const v = buf.readBigUInt64LE(off + i * 8);
    const rv = Number(v - IMAGE_BASE);
    if (rv < 0x1000 || rv > 0x8dc000) break;
    fns.push(rv);
  }
  console.log(`${td.name}`);
  console.log(`  虚表 RVA 0x${vtRva.toString(16)}  COL 0x${colRva.toString(16)}`);
  console.log(`  槽位: ${fns.map((f) => '0x' + f.toString(16)).join(', ')}\n`);
}
