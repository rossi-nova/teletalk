/**
 * 通用 PE 反汇编工具（iced-x86 内核）
 *
 * 用法：
 *   dis64.ts listing <file> <rvaHex> [指令数]      带注释的反汇编清单
 *   dis64.ts imports <file> [dll过滤]              导入表 + IAT 槽位
 *   dis64.ts exports <file>                        导出表（RVA + 名称）
 *   dis64.ts xref-iat <file> <dll过滤> [函数过滤]  扫描 .text 找经 IAT 的调用点
 *
 * 注释能力：
 *   - call/jmp 直接跳转 → 命中导出表则标注名称
 *   - call/jmp/lea [rip+X] → 命中 IAT 槽位则标注 DLL!函数
 *   - lea [rip+X] 指向只读数据 → 尝试显示字符串字面量
 */
import { readFileSync } from 'node:fs';
import { Decoder, Formatter, FormatterSyntax, Mnemonic } from 'iced-x86';
import { parsePE, rvaToOffset, type PEInfo } from './pe.js';

const [, , cmd, fileArg, a1, a2] = process.argv;
if (!cmd || !fileArg) {
  console.log('用法见文件头注释');
  process.exit(1);
}
const { buf, info } = parsePE(fileArg);

/* ---------- 导出表：RVA → 名称 ---------- */
function loadExports(): Map<number, string> {
  const m = new Map<number, string>();
  const peOff = buf.readUInt32LE(0x3c);
  const coff = peOff + 4;
  const optSize = buf.readUInt16LE(coff + 16);
  const opt = coff + 20;
  const is64 = buf.readUInt16LE(opt) === 0x20b;
  const ddOff = opt + (is64 ? 112 : 96);
  const expRva = buf.readUInt32LE(ddOff);
  if (!expRva) return m;
  const expOff = rvaToOffset(info.sections, expRva);
  if (expOff === null) return m;
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
    const name = buf.slice(noff, buf.indexOf(0, noff)).toString('latin1');
    const ord = buf.readUInt16LE(ordsOff + i * 2);
    const fRva = buf.readUInt32LE(funcsOff + ord * 4);
    m.set(fRva, name);
  }
  return m;
}

/* ---------- 导入表：IAT 槽 RVA → DLL!函数 ---------- */
function loadImports(filter?: string): Map<number, string> {
  const m = new Map<number, string>();
  const peOff = buf.readUInt32LE(0x3c);
  const coff = peOff + 4;
  const optSize = buf.readUInt16LE(coff + 16);
  const opt = coff + 20;
  const is64 = buf.readUInt16LE(opt) === 0x20b;
  const ddOff = opt + (is64 ? 112 : 96) + 8; // 第 2 个数据目录 = 导入表
  const impRva = buf.readUInt32LE(ddOff);
  if (!impRva) return m;
  let descOff = rvaToOffset(info.sections, impRva)!;
  for (;;) {
    const intRva = buf.readUInt32LE(descOff);      // OriginalFirstThunk
    const nameRva = buf.readUInt32LE(descOff + 12);
    const iatRva = buf.readUInt32LE(descOff + 16); // FirstThunk
    if (!intRva && !iatRva) break;
    const nameOff = rvaToOffset(info.sections, nameRva)!;
    const dll = buf.slice(nameOff, buf.indexOf(0, nameOff)).toString('latin1');
    if (filter && !dll.toLowerCase().includes(filter.toLowerCase())) {
      descOff += 20;
      continue;
    }
    const thunkBase = intRva || iatRva;
    const tOff0 = rvaToOffset(info.sections, thunkBase)!;
    for (let i = 0; ; i++) {
      const entry = buf.readBigUInt64LE(tOff0 + i * 8);
      if (entry === 0n) break;
      let fname: string;
      if (entry & 0x8000000000000000n) fname = `ord#${entry & 0xffffn}`;
      else {
        const byNameOff = rvaToOffset(info.sections, Number(entry))!;
        fname = buf.slice(byNameOff + 2, buf.indexOf(0, byNameOff + 2)).toString('latin1');
      }
      const slotRva = iatRva + i * 8;
      m.set(slotRva, `${dll}!${fname}`);
    }
    descOff += 20;
  }
  return m;
}

/* ---------- 工具 ---------- */
function readCString(rva: number, max = 80): string | null {
  const off = rvaToOffset(info.sections, rva);
  if (off === null) return null;
  let s = '';
  for (let i = 0; i < max; i++) {
    const b = buf[off + i];
    if (b === undefined) break;
    if (b === 0) break;
    if (b < 0x20 || b > 0x7e) return null; // 不是可打印串
    s += String.fromCharCode(b);
  }
  return s.length >= 3 ? s : null;
}

function sectionOf(rva: number): string | null {
  for (const s of info.sections) {
    if (rva >= s.virtualAddress && rva < s.virtualAddress + Math.max(s.virtualSize, s.rawSize)) return s.name;
  }
  return null;
}

const fmt = new Formatter(FormatterSyntax.Nasm);

function listing(rva: number, count: number) {
  const exportsMap = loadExports();
  const importsMap = loadImports();
  const off = rvaToOffset(info.sections, rva);
  if (off === null) { console.log('RVA 无效'); process.exit(1); }
  // 一次多读些字节，够解码 count 条
  const bytes = buf.slice(off, off + count * 15 + 64);
  const decoder = new Decoder(64, bytes, 0);
  decoder.ip = BigInt(rva);
  for (let i = 0; i < count; i++) {
    const instr = decoder.decode();
    if (instr.code === 0) break;
    const text = fmt.format(instr);
    const note: string[] = [];

    // 直接分支 → 导出/内部符号
    const isDirectBranch =
      (instr.mnemonic === Mnemonic.Call || instr.mnemonic === Mnemonic.Jmp || instr.mnemonic === Mnemonic.Jcc) &&
      instr.isCallNearIndirect === false && instr.opCount === 1 && instr.op0Kind === 1 /*NearBranch64*/;
    if (isDirectBranch) {
      const target = instr.relativeBranchTarget;
      const name = exportsMap.get(target);
      note.push(name ? `→ ${name}` : `→ sub_${target.toString(16)}`);
    }

    // rip 相对内存操作 → IAT 或字符串
    const hasRipBase = instr.isIpRelMemoryOperand === true;
    if (hasRipBase) {
      const target = Number(instr.memoryDisplacement64);
      const imp = importsMap.get(target);
      if (imp) note.push(`⇒ ${imp}`);
      else if (instr.mnemonic === Mnemonic.Lea) {
        const s = readCString(target);
        if (s) note.push(`"${s.slice(0, 60)}${s.length > 60 ? '…' : ''}"`);
        else {
          const sec = sectionOf(target);
          if (sec) note.push(`[${sec}+0x${(target).toString(16)}]`);
        }
      }
    }

    console.log(
      `  ${instr.ip.toString(16).padStart(8)}  ${text.padEnd(46)} ${note.join('  ')}`,
    );
    if (instr.mnemonic === Mnemonic.Ret) break;
  }
}

function listImports(filter?: string) {
  const m = loadImports(filter);
  for (const [slot, name] of [...m].sort((x, y) => x[0] - y[0])) {
    console.log(`  IAT 0x${slot.toString(16).padStart(8)}  ${name}`);
  }
  if (!m.size) console.log('  （无匹配导入）');
}

function xrefIat(dllFilter: string, funcFilter?: string) {
  const importsMap = loadImports(dllFilter);
  if (!importsMap.size) { console.log('无该 DLL 导入'); return; }
  // 只保留函数过滤命中的槽位
  const slots = new Map<number, string>();
  for (const [slot, name] of importsMap) {
    if (!funcFilter || name.toLowerCase().includes(funcFilter.toLowerCase())) slots.set(slot, name);
  }
  for (const n of slots.values()) console.log(`目标: ${n}`);
  console.log('');

  const text = info.sections.find((s) => s.name === '.text');
  if (!text) { console.log('无 .text'); return; }
  const tOff = text.rawPointer;
  const tLen = text.rawSize;
  const regionStart = text.virtualAddress;
  const regionEnd = regionStart + tLen;

  // 模式扫描：FF 15 disp32 (call [rip+x]) / FF 25 disp32 (jmp [rip+x])
  let found = 0;
  for (let i = 0; i < tLen - 6; i++) {
    const op = buf[tOff + i];
    if (op !== 0xff) continue;
    const modrm = buf[tOff + i + 1]!;
    if (modrm !== 0x15 && modrm !== 0x25) continue;
    const nextRva = regionStart + i + 6;
    const disp = buf.readInt32LE(tOff + i + 2);
    const target = nextRva + disp;
    const name = slots.get(target);
    if (name) {
      const kind = modrm === 0x15 ? 'call' : 'jmp';
      console.log(`  ${kind} 0x${(regionStart + i).toString(16)}  ${name}`);
      found++;
    }
  }
  console.log(`\n共 ${found} 处`);
}

function xrefRva(rvaList: string) {
  const wanted = new Set(rvaList.split(',').map((x) => parseInt(x, 16)));
  const text = info.sections.find((s) => s.name === '.text');
  if (!text) { console.log('无 .text'); return; }
  const tOff = text.rawPointer;
  const tLen = text.rawSize;
  const base = text.virtualAddress;
  // 扫 lea reg,[rip+disp32] (48/4C 8D /05) 与 mov reg,[rip+disp32] (48 8B /05)
  let hits = 0;
  for (let i = 0; i < tLen - 7; i++) {
    const p0 = buf[tOff + i]!;
    if (p0 !== 0x48 && p0 !== 0x4c) continue;
    const p1 = buf[tOff + i + 1]!;
    if (p1 !== 0x8d && p1 !== 0x8b) continue;
    const modrm = buf[tOff + i + 2]!;
    if ((modrm & 0xc7) !== 0x05) continue;
    const nextRva = base + i + 7;
    const target = nextRva + buf.readInt32LE(tOff + i + 3);
    if (wanted.has(target)) {
      const kind = p1 === 0x8d ? 'lea' : 'mov';
      console.log(`  ${kind} 0x${(base + i).toString(16)}  → 0x${target.toString(16)}`);
      hits++;
    }
  }
  console.log(`\n共 ${hits} 处`);
}

switch (cmd) {
  case 'listing':
    listing(parseInt(a1!, 16), Number(a2 ?? 120));
    break;
  case 'imports':
    listImports(a1);
    break;
  case 'exports': {
    for (const [rva, name] of [...loadExports()].sort((x, y) => x[0] - y[0])) {
      console.log(`  0x${rva.toString(16).padStart(8)}  ${name}`);
    }
    break;
  }
  case 'xref-iat':
    xrefIat(a1!, a2);
    break;
  case 'xref-rva':
    xrefRva(a1!);
    break;
  case 'iat': {
    const m = loadImports();
    for (const slot of a1!.split(',')) {
      const v = parseInt(slot, 16);
      console.log(`  0x${v.toString(16)}  ${m.get(v) ?? '(不在导入表)'}`);
    }
    break;
  }
  default:
    console.log(`未知子命令: ${cmd}`);
}
