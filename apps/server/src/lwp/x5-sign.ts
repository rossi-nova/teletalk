/**
 * x5 签名头提取
 *
 * 从运行中的钉钉进程读取 SDK 已生成的 x5-sign。
 * 原理：SDK 把签名缓存在堆上，特征是前缀 "wzMK2c002"。
 *
 * 依赖 tools/sign/build/x5-dump.exe（随仓库构建）。
 * 若不可用，回退到空对象（请求会因缺签名失败，但不会崩）。
 */
import { execFile } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

export interface X5Headers {
  'x5-sign'?: string;
  'x5-bx-version'?: string;
  'x5-sgext'?: string;
}

const DUMP_EXE = resolve(process.cwd(), 'tools/sign/build/x5-dump.exe');

interface DumpedToken {
  addr: string;
  len: number;
  value: string;
}

/** 读取当前所有缓存的 x5-sign */
export async function readX5Signs(): Promise<DumpedToken[]> {
  if (!existsSync(DUMP_EXE)) return [];
  try {
    const { stdout } = await execFileAsync(DUMP_EXE, ['--json'], {
      timeout: 5000,
      maxBuffer: 1 << 20,
    });
    const parsed = JSON.parse(stdout) as { pid: number; tokens: DumpedToken[] };
    return parsed.tokens ?? [];
  } catch {
    return [];
  }
}

/**
 * 取一个 x5 头集合。
 *
 * 注意：SDK 的签名与具体请求绑定（factor 列表），
 * 直接复用缓存值只对「同参数」的请求有效。
 * 当前实现返回最近的一个，用于验证链路。
 */
export async function getX5Headers(): Promise<X5Headers> {
  const tokens = await readX5Signs();
  if (!tokens.length) return {};
  return {
    'x5-sign': tokens[0]!.value,
    'x5-bx-version': 'pc_1.0.70.1028_0',
    'x5-sgext': 'win_reserve',
  };
}

/** 诊断：报告提取能力是否可用 */
export async function x5Status(): Promise<{
  available: boolean;
  dllPath: string;
  count: number;
  sample?: string;
}> {
  const available = existsSync(DUMP_EXE);
  const tokens = available ? await readX5Signs() : [];
  return {
    available,
    dllPath: DUMP_EXE,
    count: tokens.length,
    sample: tokens[0]?.value,
  };
}

// CLI 直跑
if (process.argv[1]?.endsWith('x5-sign.ts')) {
  const status = await x5Status();
  console.log(JSON.stringify(status, null, 2));
}
