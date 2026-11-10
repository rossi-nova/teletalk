/**
 * teletalk 精简 MITM 代理 —— 只拦截指定域名，其余一律直通。
 *
 * 设计要点：
 *   - 默认只拦 tls-desktop.dingtalk.com（主 IM 长连接），可用 --host 追加
 *   - 未命中域名：纯 TCP 隧道，零开销、零干扰
 *   - 连接复用：长连接不关闭时按 5 秒增量落盘，避免内存堆积
 *   - 上游可直连（默认）或经 mihomo
 *
 * 用法：
 *   node proxy.mjs [--port 8888] [--host a.com,b.com]
 * 环境：
 *   UPSTREAM_HOST=127.0.0.1 UPSTREAM_PORT=7897   经上游代理（设为 none 直连）
 *   ALLOW_BAD_UPSTREAM=1                          跳过上游证书校验
 */
import http from 'node:http';
import net from 'node:net';
import tls from 'node:tls';
import { createWriteStream, mkdirSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { certForHost } from './certs.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const arg = (n, d) => {
  const i = process.argv.indexOf(`--${n}`);
  return i !== -1 && process.argv[i + 1] ? process.argv[i + 1] : d;
};

const PORT = Number(arg('port', '8888'));
const DEFAULT_HOSTS = 'tls-desktop.dingtalk.com';
const HOSTS = new Set(arg('host', DEFAULT_HOSTS).split(',').map((s) => s.trim()).filter(Boolean));

const OUT_DIR = join(HERE, arg('out', '../../captures'));
const RUN_DIR = join(OUT_DIR, `run-${new Date().toISOString().replace(/[:.]/g, '-')}`);
const FLUSH_MS = Number(arg('flush', '5000'));

const UP = (process.env.UPSTREAM_HOST ?? 'none').toLowerCase() === 'none'
  ? null
  : { host: process.env.UPSTREAM_HOST || '127.0.0.1', port: Number(process.env.UPSTREAM_PORT || 7897) };
const ALLOW_BAD = process.env.ALLOW_BAD_UPSTREAM === '1';

if (!existsSync(RUN_DIR)) mkdirSync(RUN_DIR, { recursive: true });
const log = (...a) => console.log(`[${new Date().toISOString().slice(11, 23)}]`, ...a);

const CONN_DIR = join(RUN_DIR, 'conn');
mkdirSync(CONN_DIR, { recursive: true });

let connSeq = 0;
/** 为一条连接建独立目录，c2s/s2c 分段编号写入 */
function openConn(host) {
  const id = String(++connSeq).padStart(4, '0');
  const dir = join(CONN_DIR, `${id}-${host}`);
  mkdirSync(dir, { recursive: true });
  let cSeq = 0, sSeq = 0;
  const meta = { id, host, startedAt: new Date().toISOString(), chunks: { c2s: 0, s2c: 0 } };
  return {
    meta,
    c2s(buf) { createWriteStream(join(dir, `${String(++cSeq).padStart(4, '0')}-c2s.bin`)).end(buf); meta.chunks.c2s++; },
    s2c(buf) { createWriteStream(join(dir, `${String(++sSeq).padStart(4, '0')}-s2c.bin`)).end(buf); meta.chunks.s2c++; },
  };
}

/** 经上游建立隧道 */
function openTunnel(host, port) {
  return new Promise((resolve, reject) => {
    if (!UP) {
      const s = net.connect({ host, port }, () => resolve(s));
      s.on('error', reject);
      return;
    }
    const raw = net.connect(UP.port, UP.host, () => {
      raw.write(`CONNECT ${host}:${port} HTTP/1.1\r\nHost: ${host}:${port}\r\n\r\n`);
    });
    let buf = Buffer.alloc(0);
    const onData = (c) => {
      buf = Buffer.concat([buf, c]);
      const i = buf.indexOf('\r\n\r\n');
      if (i === -1) return;
      raw.removeListener('data', onData);
      const head = buf.slice(0, i).toString();
      if (!/^HTTP\/1\.[01] 200/.test(head)) { raw.destroy(); reject(new Error(head.split('\r\n')[0])); return; }
      const rest = buf.slice(i + 4);
      if (rest.length) raw.unshift(rest);
      resolve(raw);
    };
    raw.on('data', onData);
    raw.once('error', reject);
  });
}

const server = http.createServer();

server.on('connect', (req, clientSocket, head) => {
  const [host, portStr] = (req.url || '').split(':');
  const port = Number(portStr || 443);

  // —— 非目标域名：纯隧道直通，零干扰 ——
  if (!HOSTS.has(host)) {
    const up = net.connect(port, host, () => {
      clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head?.length) up.write(head);
      up.pipe(clientSocket);
      clientSocket.pipe(up);
    });
    up.on('error', () => clientSocket.destroy());
    clientSocket.on('error', () => up.destroy());
    return;
  }

  let site;
  try { site = certForHost(host); }
  catch (e) { log('cert err', host, e.message); clientSocket.destroy(); return; }

  const conn = openConn(host);
  log('intercept', host, '#' + conn.meta.id);

  clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n', () => {
    const ls = tls.createServer({ key: site.key, cert: site.cert }, (client) => {
      if (head?.length) client.unshift(head);

      openTunnel(host, port).then((tunnel) => {
        const up = tls.connect({ socket: tunnel, servername: host, rejectUnauthorized: !ALLOW_BAD });

        up.once('secureConnect', () => {
          log('stream up', host, '#' + conn.meta.id);

          // 增量落盘：每 FLUSH_MS 把累积的数据写成独立文件
          const pendC = [], pendS = [];
          const timer = setInterval(() => {
            if (pendC.length) { conn.c2s(Buffer.concat(pendC)); pendC.length = 0; }
            if (pendS.length) { conn.s2c(Buffer.concat(pendS)); pendS.length = 0; }
          }, FLUSH_MS);
          timer.unref();

          const finish = (why) => {
            clearInterval(timer);
            if (pendC.length) conn.c2s(Buffer.concat(pendC));
            if (pendS.length) conn.s2c(Buffer.concat(pendS));
            log('close', host, '#' + conn.meta.id, why,
              `c2s=${conn.meta.chunks.c2s} s2c=${conn.meta.chunks.s2c}`);
          };

          client.on('data', (c) => { pendC.push(c); up.write(c); });
          up.on('data', (c) => { pendS.push(c); client.write(c); });
          client.on('end', () => up.end());
          up.on('end', () => client.end());
          client.on('close', () => finish('client-close'));
          up.on('close', () => finish('upstream-close'));
          client.on('error', (e) => log('client err', host, e.message));
          up.on('error', (e) => { log('up err', host, e.message); client.destroy(); });
        });
        up.on('error', (e) => { log('up tls err', host, e.message); client.destroy(); });
      }).catch((e) => { log('tunnel err', host, e.message); client.destroy(); });
    });
    ls.on('tlsClientError', (e) => log('tls err', host, e.message));
    ls.emit('connection', clientSocket);
  });
});

server.listen(PORT, () => {
  log(`MITM :${PORT}`);
  log(`拦截: ${[...HOSTS].join(', ')}`);
  log(`上游: ${UP ? `${UP.host}:${UP.port}` : '直连'}`);
  log(`输出: ${RUN_DIR}`);
});
process.on('SIGINT', () => { server.close(); process.exit(0); });
