/**
 * 混淆跳板自动跟随器
 *
 * SDK 的函数入口统一用「常量算术 + jmp/push-ret + call/pop」跳板隐藏真实主体。
 * 跳板输入全部是编译期常量，用小型符号执行即可折叠出真实目标。
 *
 * 用法: npx tsx tools/disasm/follow.ts <file> <rvaHex> [--scan] [--chain]
 *   --scan   从入口线性扫描到第一个「槽写常量」，再开始折叠
 *   --chain  终点若仍是跳板则继续跟进，直到真主体
 */
import { Decoder, Formatter, FormatterSyntax } from 'iced-x86';
import { parsePE, rvaToOffset } from './pe.js';

const [, , file, rvaHex] = process.argv;
const startRva = parseInt(rvaHex!, 16);
const { buf, info } = parsePE(file!);
const fmt = new Formatter(FormatterSyntax.Nasm);

const regs = new Map<string, bigint>();
const ptrs = new Map<string, string>();
const mem = new Map<string, bigint>();

function readAt(rva: number, n: number) {
  const off = rvaToOffset(info.sections, rva);
  if (off === null) throw new Error(`RVA 0x${rva.toString(16)} 无法映射`);
  return buf.slice(off, off + n);
}

const imm = (s: string) => BigInt.asIntN(64, BigInt(s));
/** NASM 风格后缀 h → 去掉（只删紧跟在 hex 数字后的 h） */
const stripH = (s: string) => s.replace(/([0-9A-F])h\b/g, '$1');

function* trace(rva: number): Generator<string, number> {
  let cur = rva;
  let steps = 0;
  let lastPush: string | null = null;

  for (;;) {
    if (++steps > 60) throw new Error('步数超限（可能不是跳板）');
    const bytes = readAt(cur, 32);
    const dec = new Decoder(64, bytes, 0);
    dec.ip = BigInt(cur);
    const ins = dec.decode();
    const raw = fmt.format(ins);
    const text = stripH(raw);
    const next = cur + ins.length;

    yield `${cur.toString(16).padStart(8)}  ${raw}`;

    let m: RegExpMatchArray | null;

    if ((m = text.match(/^push (\w+)$/))) { lastPush = m[1]!; cur = next; continue; }
    if (text === 'ret') {
      if (lastPush) {
        const v = regs.get(lastPush);
        if (v === undefined) throw new Error(`push ${lastPush} 非常量`);
        cur = Number(v);
        lastPush = null;
        continue;
      }
      throw new Error('裸 ret');
    }
    // 直接跳转（链式跳板）
    if ((m = text.match(/^jmp (?:short )?([0-9A-F]+)$/))) {
      cur = Number('0x' + m[1]!);
      lastPush = null;
      continue;
    }
    if ((m = text.match(/^jmp (\w+)$/))) {
      const v = regs.get(m[1]!);
      if (v === undefined) throw new Error(`jmp ${m[1]} 非常量`);
      cur = Number(v);
      lastPush = null;
      continue;
    }
    // jcc 对（同目标互补条件 = 无条件跳）
    if (/^j[a-z]+ /.test(text) && (m = text.match(/^j[a-z]+ (short )?([0-9A-F]+)$/))) {
      const t1 = m[2]!;
      const ins2 = (() => { const d = new Decoder(64, readAt(next, 16), 0); d.ip = BigInt(next); return d.decode(); })();
      const t2 = stripH(fmt.format(ins2)).match(/^j[a-z]+ (short )?([0-9A-F]+)$/);
      if (t2 && t2[2] === t1) { cur = Number('0x' + t1); continue; }
      return cur;
    }
    // call reg（目标是 call+pop 跳板则继续，否则停止）
    if ((m = text.match(/^call (\w+)$/))) {
      const v = regs.get(m[1]!);
      if (v === undefined) throw new Error(`call ${m[1]} 非常量`);
      const dest = Number(v);
      const b = readAt(dest, 4);
      const isPop = (b[0]! >= 0x58 && b[0]! <= 0x5f) || (b[0] === 0x41 && b[1]! >= 0x58 && b[1]! <= 0x5f);
      if (isPop) { cur = dest; continue; }
      return cur;
    }
    // 槽写常量
    if ((m = text.match(/^mov dword \[(rbp-[0-9A-F]+|rsp\+[0-9A-F]+|rbp\+[0-9A-F]+)\],([0-9A-F]+)$/))) {
      mem.set(`[${m[1]!}]`, imm('0x' + m[2]!));
      cur = next; continue;
    }
    // lea reg,[rel X]
    if ((m = text.match(/^lea (\w+),\[rel ([0-9A-F]+)\]$/))) { regs.set(m[1]!, imm('0x' + m[2]!)); cur = next; continue; }
    // lea reg,[slot]
    if ((m = text.match(/^lea (\w+),\[(rbp-[0-9A-F]+|rsp\+[0-9A-F]+)\]$/))) { ptrs.set(m[1]!, `[${m[2]!}]`); cur = next; continue; }
    // mov reg,imm
    if ((m = text.match(/^mov (\w+),([0-9A-F]+)$/))) { regs.set(m[1]!, imm('0x' + m[2]!)); cur = next; continue; }
    // movsx reg,word [reg]
    if ((m = text.match(/^movsx (\w+),word \[(\w+)\]$/))) {
      const slot = ptrs.get(m[2]!);
      const v = slot !== undefined ? mem.get(slot) : undefined;
      if (v === undefined) throw new Error(`movsx 槽 ${m[2]} 非常量`);
      regs.set(m[1]!, BigInt.asIntN(16, v));
      cur = next; continue;
    }
    if ((m = text.match(/^not (\w+)$/))) {
      const v = regs.get(m[1]!);
      if (v === undefined) throw new Error(`not ${m[1]} 非常量`);
      regs.set(m[1]!, ~v);
      cur = next; continue;
    }
    // 立即数分支在前，避免立即数被当成寄存器
    if ((m = text.match(/^(add|sub|xor) (\w+),([0-9A-F]+)$/))) {
      const a = regs.get(m[2]!);
      if (a === undefined) throw new Error(`${m[1]} ${m[2]} 非常量`);
      const b = imm('0x' + m[3]!);
      regs.set(m[2]!, m[1] === 'add' ? a + b : m[1] === 'sub' ? a - b : a ^ b);
      cur = next; continue;
    }
    if ((m = text.match(/^(add|sub|xor) (\w+),(\w+)$/))) {
      const a = regs.get(m[2]!), b = regs.get(m[3]!);
      if (a === undefined || b === undefined) throw new Error(`${m[1]} 操作数非常量`);
      regs.set(m[2]!, m[1] === 'add' ? a + b : m[1] === 'sub' ? a - b : a ^ b);
      cur = next; continue;
    }
    return cur;
  }
}

const verbose = process.env.VERBOSE === '1';

/** scan 模式：线性找到第一个「槽写常量」 */
function findTrampolineStart(rva: number): number {
  let cur = rva;
  for (let i = 0; i < 80; i++) {
    const dec = new Decoder(64, readAt(cur, 16), 0);
    dec.ip = BigInt(cur);
    const ins = dec.decode();
    if (ins.code === 0) throw new Error('解码失败');
    const t = stripH(fmt.format(ins));
    if (/^mov dword \[(rbp-[0-9A-F]+|rsp\+[0-9A-F]+)\],[0-9A-F]+$/.test(t)) return cur;
    if (process.env.DEBUG === '1') console.error(`  scan ${cur.toString(16)}: ${t}`);
    cur += ins.length;
  }
  throw new Error('前 80 条内未发现跳板特征');
}

const scan = process.argv.includes('--scan');
const chain = process.argv.includes('--chain');

function runTrace(rva: number): number {
  const g = (function* () { return yield* trace(rva); })();
  let r = g.next();
  while (!r.done) {
    if (verbose) console.log('  ' + r.value);
    r = g.next();
  }
  return r.value as number;
}

function isTrampoline(rva: number): boolean {
  try { findTrampolineStart(rva); return true; } catch { return false; }
}

try {
  let cur = scan ? findTrampolineStart(startRva) : startRva;
  let hops = 0;
  let endpoint = runTrace(cur);
  while (chain && endpoint !== cur && isTrampoline(endpoint) && hops < 10) {
    cur = findTrampolineStart(endpoint);
    endpoint = runTrace(cur);
    hops++;
  }
  console.log('跳板终点: 0x' + endpoint.toString(16) + '  (entry 0x' + startRva.toString(16) + ', hops ' + hops + ')');
} catch (e) {
  console.error('跟随失败 @ 0x' + startRva.toString(16) + ': ' + (e as Error).message);
  process.exit(1);
}
