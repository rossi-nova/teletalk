/**
 * 测试 node:ffi 调用 SecurityGuardSDK64.dll
 * 先试最简单的导出 —— 确认 FFI 链路可用
 */
import { open, define } from 'node:ffi';

const dllPath = 'C:/Program Files (x86)/DingDing/main/current/SecurityGuardSDK64.dll';

try {
  const lib = open(dllPath);
  console.log('✓ 已加载 DLL');

  // 先试最简单的 getCompatibelDcpToken 看看能否调用
  // 接着试 initUMID 初始化
  const fn = define('initUMID', lib, { 
    type: 'function',
    parameters: [],
    result: 'int32',
  });
  console.log('函数定义:', fn.name);
} catch (e) {
  console.error('✗', (e as Error).message);
}
