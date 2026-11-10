/** 用真实抓包样本验证发送构造器 */
import { readFileSync } from 'node:fs';
import { buildSendBody, paramsFromSample } from '../apps/server/src/lwp/send-builder.js';
import { parseFrames } from '../apps/server/src/lwp/frame.js';

const sampleFile = process.argv[2];
if (!sampleFile) {
  console.error('用法: tsx scripts/test-send-builder.ts <抓包文件>');
  process.exit(1);
}

const { frames } = parseFrames(readFileSync(sampleFile));
const target = frames.find((f) => f.kind === 'req' && f.uri === '/r/IDLSend/send');
if (!target) {
  console.error('样本中未找到 IDLSend/send');
  process.exit(1);
}

const expected = target.body;
const actual = buildSendBody(paramsFromSample());

console.log(`样本 ${expected.length}B  构造 ${actual.length}B`);
if (expected.equals(actual)) {
  console.log('✓ 字节完全一致');
  process.exit(0);
}

console.log('✗ 不一致，首个差异：');
const n = Math.max(expected.length, actual.length);
for (let i = 0; i < n; i++) {
  if (expected[i] !== actual[i]) {
    console.log(`  偏移 ${i}: 样本=0x${(expected[i] ?? 0).toString(16)} 构造=0x${(actual[i] ?? 0).toString(16)}`);
    console.log(`  样本: ${expected.slice(Math.max(0, i - 16), i + 16).toString('hex')}`);
    console.log(`  构造: ${actual.slice(Math.max(0, i - 16), i + 16).toString('hex')}`);
    break;
  }
}
process.exit(1);
