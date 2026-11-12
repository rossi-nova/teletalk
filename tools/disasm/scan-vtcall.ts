/** 扫描 MainFrame baxia 区域的虚表间接调用 */
import { readFileSync } from 'node:fs';
const b = readFileSync('C:/Program Files (x86)/DingDing/main/current_new/MainFrame.dll');
const lo = 0x4ba0000 - 0x1000 + 0x400, hi = 0x4ba8000 - 0x1000 + 0x400;
const REG = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi'];
for (let i = lo; i < hi; i++) {
  if (b[i] !== 0xff) continue;
  const m = b[i + 1]!;
  if (m >= 0x50 && m <= 0x57) {
    console.log(`RVA 0x${(i + 0x1000 - 0x400).toString(16)}  call [${REG[m - 0x50]}+0x${b[i + 2]!.toString(16)}]`);
  } else if (m >= 0x90 && m <= 0x97) {
    console.log(`RVA 0x${(i + 0x1000 - 0x400).toString(16)}  call [${REG[m - 0x90]}+0x${(b.readInt32LE(i + 2) >>> 0).toString(16)}]`);
  } else if (m >= 0x10 && m <= 0x17) {
    console.log(`RVA 0x${(i + 0x1000 - 0x400).toString(16)}  call [${REG[m - 0x10]}]`);
  }
}
