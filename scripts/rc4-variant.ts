/**
 * SDK 内 RC4 变体离线复算
 *
 * 逆向自 SDK RVA 0x11d952-0x11db58：
 *   S[i] = i  (256 项，0x8DE540 起)
 *   KSA（按步长 2 展开，两个密钥字节 0x71 / 0x45 交替）：
 *     j = 0
 *     for (i = 0; i < 256; i += 2) {
 *        d = S[i];  j = (j + d + 0x71) & 0xff
 *        S[i] = S[j]; S[j] = d;
 *        c = S[i+1]; k = (j + c + 0x45) & 0xff
 *        S[i+1] = S[k]; S[k] = c;
 *     }
 *   PRGA（标准），输出 11 字节
 */
import { readFileSync } from 'node:fs';
import { parsePE, rvaToOffset } from '../tools/disasm/pe.js';

const { buf, info } = parsePE('C:/Program Files (x86)/DingDing/main/current_new/SecurityGuardSDK64.dll');
const read = (rva: number, n: number) => {
  const off = rvaToOffset(info.sections, rva)!;
  return buf.slice(off, off + n);
};

function rc4Variant(src: Buffer, outLen: number): Buffer {
  const S = new Uint8Array(256);
  for (let i = 0; i < 256; i++) S[i] = i;

  let j = 0;
  for (let i = 0; i < 256; i += 2) {
    const d = S[i]!;
    j = (j + d + 0x71) & 0xff;
    S[i] = S[j]!;
    S[j] = d;

    const c = S[i + 1]!;
    const k = (j + c + 0x45) & 0xff;
    S[i + 1] = S[k]!;
    S[k] = c;
  }

  const out = Buffer.alloc(outLen);
  let si = 0;
  j = 0;
  for (let n = 0; n < outLen; n++) {
    si = (si + 1) & 0xff;
    j = (j + S[si]!) & 0xff;
    const t = S[si]!; S[si] = S[j]!; S[j] = t;
    out[n] = src[n]! ^ S[(S[si]! + S[j]!) & 0xff]!;
  }
  return out;
}

const src = read(0x8dfb25, 11);
const out = rc4Variant(src, 11);
console.log('明文源 (0x8DFB25):', src.toString('hex'));
console.log('RC4变体输出      :', out.toString('hex'));
console.log('ascii            :', JSON.stringify(out.toString('latin1')));
