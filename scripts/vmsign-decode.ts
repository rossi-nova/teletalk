/**
 * vmsign_config_fi 解码器（已验证）
 *
 * 逆向自 SDK RVA 0x107290-0x1072D9 的 36 字节解码循环。
 *
 * 算法：比特流整体左移 1 位
 *   out[0] = 0x33（预置，不覆盖）
 *   out[i] = (ct[i] << 1) | (ct[i-1] >> 7)    for i = 1..35
 *
 * 解码结果：3be229e1-301d-4639-b88a-16997824d71b
 *           （标准 GUID，配置 ID）
 */
import { readFileSync } from 'node:fs';
import { parsePE, rvaToOffset } from '../tools/disasm/pe.js';

const SDK = 'C:/Program Files (x86)/DingDing/main/current_new/SecurityGuardSDK64.dll';

export function decodeVmsign(sdkPath: string, rva: number, len = 36): string {
  const { buf, info } = parsePE(sdkPath);
  const src = rvaToOffset(info.sections, rva)!;
  const out = Buffer.alloc(len);
  out[0] = 0x33;
  for (let i = 1; i < len; i++) {
    out[i] = (((buf[src + i]! << 1) & 0xff) | ((buf[src + i - 1]! >> 7) & 1)) & 0xff;
  }
  return out.toString('latin1').replace(/\0.*$/, '');
}

// CLI
if (process.argv[1]?.endsWith('vmsign-decode.ts') || process.argv[1]?.endsWith('vmsign-final.ts')) {
  const rva = process.argv[2] ? parseInt(process.argv[2]!, 16) : 0x8dfdd0;
  const len = Number(process.argv[3] ?? 36);

  const result = decodeVmsign(SDK, rva, len);
  console.log(`RVA 0x${rva.toString(16)} 解码 ${len} 字节:`);
  console.log(`  ${JSON.stringify(result)}`);

  // 验证 GUID
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(result)) {
    console.log('  ✓ 标准 GUID 格式');
  } else {
    console.log('  （非 GUID）');
  }
}
