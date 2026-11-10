/**
 * 站点证书签发与缓存。
 * 用 openssl CLI 签（Node 原生没有签发能力），结果缓存在 certs/sites/。
 */
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const CERT_DIR = join(HERE, 'certs');
const SITE_DIR = join(CERT_DIR, 'sites');
const CA_KEY = join(CERT_DIR, 'ca.key');
const CA_CRT = join(CERT_DIR, 'ca.crt');

function openssl(args, input) {
  return execFileSync('openssl', args, {
    input,
    env: { ...process.env, MSYS_NO_PATHCONV: '1' },
    stdio: ['pipe', 'pipe', 'pipe'],
  });
}

/** 为一个 host 签发证书，返回 {key, cert}；已存在则复用。 */
export function certForHost(host) {
  if (!existsSync(SITE_DIR)) mkdirSync(SITE_DIR, { recursive: true });

  const safe = host.replace(/[^a-zA-Z0-9._-]/g, '_');
  const keyPath = join(SITE_DIR, `${safe}.key`);
  const crtPath = join(SITE_DIR, `${safe}.crt`);

  if (existsSync(keyPath) && existsSync(crtPath)) {
    return { key: readFileSync(keyPath, 'utf8'), cert: readFileSync(crtPath, 'utf8') };
  }

  // 生成站点私钥
  openssl(['genrsa', '-out', keyPath, '2048']);

  // CSRs
  const csrPath = join(SITE_DIR, `${safe}.csr`);
  openssl(['req', '-new', '-key', keyPath, '-out', csrPath, '-subj', `/CN=${host}`]);

  // SAN 扩展配置（域名 + 通配）
  const extPath = join(SITE_DIR, `${safe}.ext`);
  writeFileSync(extPath, [
    'basicConstraints=CA:FALSE',
    'keyUsage=digitalSignature,keyEncipherment',
    'extendedKeyUsage=serverAuth',
    'authorityKeyIdentifier=keyid:always',
    'subjectKeyIdentifier=hash',
    `subjectAltName=DNS:${host},DNS:*.${host}`,
  ].join('\n'));

  openssl([
    'x509', '-req', '-in', csrPath,
    '-CA', CA_CRT, '-CAkey', CA_KEY, '-CAcreateserial',
    '-out', crtPath, '-days', '825', '-sha256', '-extfile', extPath,
  ]);

  return { key: readFileSync(keyPath, 'utf8'), cert: readFileSync(crtPath, 'utf8') };
}

export const CA_CERT_PATH = CA_CRT;
