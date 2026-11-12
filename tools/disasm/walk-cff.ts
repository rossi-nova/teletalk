/**
 * 展平状态链遍历器
 *
 * getSecurityToken 等函数展平后，每个基本块形如：
 *   mov dword [rsp+64h], STATE
 *   lea rcx, [rel NEXT]
 *   <常量算术>
 *   add rcx, imm
 *   mov dword [rsp+68h], NEXT_STATE
 *   call rcx        ← 跳板（call+pop 或 push/ret）
 *   ...
 *   jmp <block>     ← 块末尾直接跳转
 *
 * 本工具从入口出发，边走边收集：
 *   - 遇到间接调用/跳转且目标是常量 → 跟随
 *   - 遇到直接 jmp → 跟随
 *   - 遇到 ret / 外部调用 → 记录并停止该分支
 *
 * 用法: npx tsx tools/disasm/walk-cff.ts <file> <rvaHex> [最多块数]
 */
import { Decoder, Formatter, FormatterSyntax, Mnemonic } from 'iced-x86';
import { parsePE, rvaToOffset } from './pe.js';

const [, , file, rvaHex, maxArg] = process.argv;
const MAX_BLOCKS = Number(maxArg ?? 400);
const { buf, info } = parsePE(file!);
const fmt = new Formatter(FormatterSyntax.Nasm);
const stripH = (s: string) => s.replace(/([0-9A-F])h\b/g, '$1');

function decodeAt(rva: number) {
  const off = rvaToOffset(info.sections, rva);
  if (off === null) return null;
  const dec = new Decoder(64, buf.slice(off, off + 16), 0);
  dec.ip = BigInt(rva);
  const ins = dec.decode();
  if (ins.code === 0) return null;
  return { ins, text: stripH(fmt.format(ins)) };
}

interface Block {
  start: number;
  end: number;
  insns: string[];
  next: number | null;
  reason: string;
}

const blocks: Block[] = [];
const visited = new Set<number>();
let queue = [parseInt(rvaHex!, 16)];

// 跨块保持：寄存器与槽位状态（跳板链会跨块传递）
const regs = new Map<string, bigint>();
const mem = new Map<string, bigint>();
const ptrs = new Map<string, string>();

while (queue.length && blocks.length < MAX_BLOCKS) {
  const start = queue.shift()!;
  if (visited.has(start)) continue;
  visited.add(start);

  const b: Block = { start, end: start, insns: [], next: null, reason: '' };
  let cur = start;

  for (let step = 0; step < 400; step++) {
    const d = decodeAt(cur);
    if (!d) { b.reason = '解码失败'; break; }
    const { ins, text } = d;
    b.insns.push(`${cur.toString(16).padStart(8)}  ${fmt.format(ins)}`);
    cur += ins.length;
    b.end = cur;

    let m: RegExpMatchArray | null;

    // 直接跳转 → 跟随
    if ((m = text.match(/^jmp (?:short )?([0-9A-F]+)$/))) {
      b.next = Number('0x' + m[1]!); b.reason = '直接 jmp'; break;
    }
    // jcc → 记录目标并继续（分支）
    if ((m = text.match(/^j(?:[a-z]+) (?:short )?([0-9A-F]+)$/))) {
      const t = Number('0x' + m[1]!);
      if (!visited.has(t) && !queue.includes(t)) queue.push(t);
      continue;
    }
    // jmp reg
    if ((m = text.match(/^jmp (\w+)$/))) {
      const v = regs.get(m[1]!);
      if (v !== undefined) { b.next = Number(v); b.reason = `jmp ${m[1]}=0x${v.toString(16)}`; }
      else b.reason = `jmp ${m[1]} 未知`;
      break;
    }
    // push reg + ret = 尾跳（跳板出口）
    if (text === 'ret' && b.insns.length >= 2 && /push \w+$/.test(b.insns[b.insns.length - 2]!)) {
      const pm = b.insns[b.insns.length - 2]!.match(/push (\w+)$/);
      const v = pm ? regs.get(pm[1]!) : undefined;
      if (v !== undefined) { b.next = Number(v); b.reason = `push/ret 尾跳 → 0x${Number(v).toString(16)}`; }
      else b.reason = `push/ret 未知目标`;
      break;
    }
    if (text === 'ret') { b.reason = 'ret（返回）'; break; }

    // 槽写
    if ((m = text.match(/^mov dword \[(rsp\+[0-9A-F]+|rbp-[0-9A-F]+|rbp\+[0-9A-F]+)\],([0-9A-F]+)$/))) {
      mem.set(`[${m[1]!}]`, BigInt.asIntN(64, BigInt('0x' + m[2]!))); continue;
    }
    if ((m = text.match(/^lea (\w+),\[rel ([0-9A-F]+)\]$/))) { regs.set(m[1]!, BigInt('0x' + m[2]!)); continue; }
    if ((m = text.match(/^lea (\w+),\[(rsp\+[0-9A-F]+|rbp-[0-9A-F]+)\]$/))) { ptrs.set(m[1]!, `[${m[2]!}]`); continue; }
    if ((m = text.match(/^mov (\w+),([0-9A-F]+)$/))) { regs.set(m[1]!, BigInt.asIntN(64, BigInt('0x' + m[2]!))); continue; }
    if ((m = text.match(/^movsx (\w+),word \[(\w+)\]$/))) {
      const slot = ptrs.get(m[2]!);
      const v = slot ? mem.get(slot) : undefined;
      if (v !== undefined) regs.set(m[1]!, BigInt.asIntN(16, v));
      continue;
    }
    if ((m = text.match(/^not (\w+)$/))) {
      const v = regs.get(m[1]!); if (v !== undefined) regs.set(m[1]!, ~v); continue;
    }
    if ((m = text.match(/^(add|sub|xor) (\w+),([0-9A-F]+)$/))) {
      const a = regs.get(m[2]!);
      if (a !== undefined) {
        const k = BigInt.asIntN(64, BigInt('0x' + m[3]!));
        regs.set(m[2]!, m[1] === 'add' ? a + k : m[1] === 'sub' ? a - k : a ^ k);
      }
      continue;
    }
    if ((m = text.match(/^(add|sub|xor) (\w+),(\w+)$/))) {
      const a = regs.get(m[2]!), bb = regs.get(m[3]!);
      if (a !== undefined && bb !== undefined) {
        regs.set(m[2]!, m[1] === 'add' ? a + bb : m[1] === 'sub' ? a - bb : a ^ bb);
      }
      continue;
    }
    // call reg → 常量则跟随（跳板），否则记录外部调用
    if ((m = text.match(/^call (\w+)$/))) {
      const v = regs.get(m[1]!);
      if (v !== undefined) {
        const dest = Number(v);
        const dd = decodeAt(dest);
        const isTramp = dd && /^(pop r\w+|ret)$/.test(dd.text);
        if (isTramp) { b.next = dest; b.reason = `call ${m[1]}（跳板→0x${dest.toString(16)}）`; }
        else { b.reason = `外部 call 0x${dest.toString(16)}`; }
      } else {
        b.reason = `call ${m[1]} 未知`;
      }
      break;
    }
    if ((m = text.match(/^call (?:[0-9A-F]+)$/))) { b.reason = `外部 ${text}`; break; }
  }

  blocks.push(b);
  if (b.next !== null && !visited.has(b.next)) queue.push(b.next);
  else queue = [...new Set(queue)];
}

// 输出
console.log(`共遍历 ${blocks.length} 个块\n`);
for (const b of blocks) {
  console.log(`\n######## 块 0x${b.start.toString(16)} -> 0x${b.end.toString(16)}  [${b.reason}]`);
  for (const l of b.insns.slice(0, 40)) console.log('  ' + l);
  if (b.insns.length > 40) console.log(`  ...（共 ${b.insns.length} 条）`);
}
