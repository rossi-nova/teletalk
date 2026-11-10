/**
 * 协议探针：把 fixtures/ 里的抓包样本重放成请求，验证 Node 侧能否复现。
 *
 * 用法：
 *   pnpm probe <fixture.json>
 *
 * fixture 格式（脱敏后的单条请求）：
 * {
 *   "id": "M1",
 *   "method": "POST",
 *   "url": "https://...",
 *   "headers": { "x-xxx": "{{SECRET}}", ... },
 *   "body": "{...}",
 *   "note": "人写的说明"
 * }
 *
 * 环境变量（放在本地 .env，不进版本库）：
 *   DT_COOKIE           登录态 cookie 串
 *   DT_TOKEN            主要 token
 *   DT_DEVICE_ID        设备标识
 *
 * 输出：状态码、耗时、响应头、响应体（超过 4KB 只存文件）。
 */
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';

interface Fixture {
  id: string;
  method: string;
  url: string;
  headers?: Record<string, string>;
  body?: string;
  note?: string;
}

/** 把 {{VAR}} 替换成环境变量值；缺失时保留原样并告警。 */
function interpolate(input: string): { text: string; missing: string[] } {
  const missing: string[] = [];
  const text = input.replace(/\{\{([A-Z0-9_]+)\}\}/g, (_m, name: string) => {
    const v = process.env[name];
    if (v === undefined) {
      missing.push(name);
      return `{{${name}}}`;
    }
    return v;
  });
  return { text, missing };
}

async function main() {
  const fixturePath = process.argv[2];
  if (!fixturePath) {
    console.error('用法: pnpm probe <fixture.json>');
    process.exit(1);
  }

  const raw = await readFile(fixturePath, 'utf8');
  const rawFixture = JSON.parse(raw) as Fixture | Fixture[];
  const fixtures = Array.isArray(rawFixture) ? rawFixture : [rawFixture];

  const outDir = join('docs', 'research', 'probe-out');
  if (!existsSync(outDir)) await mkdir(outDir, { recursive: true });

  for (const fixture of fixtures) {
    const { text: url, missing: urlMissing } = interpolate(fixture.url);
    const headers: Record<string, string> = {};
    const missing: string[] = [...urlMissing];

    for (const [k, v] of Object.entries(fixture.headers ?? {})) {
      const { text, missing: m } = interpolate(v);
      headers[k] = text;
      missing.push(...m);
    }

    let body: string | undefined;
    if (fixture.body) {
      const r = interpolate(fixture.body);
      body = r.text;
      missing.push(...r.missing);
    }

    if (missing.length) {
      console.warn(`[${fixture.id}] 未解析的占位符: ${[...new Set(missing)].join(', ')}`);
    }

    const started = performance.now();
    let status = 0;
    let respHeaders: Record<string, string> = {};
    let respText = '';
    let error: string | undefined;

    try {
      const resp = await fetch(url, {
        method: fixture.method,
        headers,
        body: fixture.method === 'GET' || fixture.method === 'HEAD' ? undefined : body,
      });
      status = resp.status;
      respHeaders = Object.fromEntries(resp.headers.entries());
      respText = await resp.text();
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    }

    const elapsed = Math.round(performance.now() - started);

    const result = {
      id: fixture.id,
      note: fixture.note,
      status,
      elapsedMs: elapsed,
      error,
      responseHeaders: respHeaders,
      responseBodyPreview: respText.length > 4096 ? `${respText.slice(0, 4096)}…(截断)` : respText,
      responseBodyLength: respText.length,
    };

    const safeId = basename(fixture.id || 'fixture').replace(/[^\w.-]/g, '_');
    const outPath = join(outDir, `${safeId}.json`);
    await writeFile(outPath, JSON.stringify(result, null, 2), 'utf8');

    const mark = error ? '✗' : status >= 200 && status < 300 ? '✓' : '!';
    console.log(`${mark} [${fixture.id}] ${fixture.method} ${status || '-'} ${elapsed}ms → ${outPath}`);
    if (error) console.log(`   ${error}`);
    else if (respText.length) console.log(`   ${respText.slice(0, 200).replace(/\s+/g, ' ')}`);
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
