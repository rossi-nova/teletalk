/**
 * teletalk MITM 代理（HTTP CONNECT 隧道 + TLS 解密 + 抓包落盘）
 *
 * 用法：
 *   node proxy.mjs [--port 8888] [--out ../../captures]
 *
 * 只记录，不修改流量。白名单外的域名走纯隧道直通，不解密。
 */
import http from 'node:http';
import net from 'node:net';
import tls from 'node:tls';
import { createWriteStream, mkdirSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { certForHost } from './certs.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));

function arg(name, fallback) {
  const i = process.argv.indexOf(`--${name}`);
  return i !== -1 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}

const PORT = Number(arg('port', '8888'));
const OUT_DIR = join(HERE, arg('out', '../../captures'));
const RUN_DIR = join(OUT_DIR, `run-${new Date().toISOString().replace(/[:.]/g, '-')}`);

const INTERCEPT = [/(^|\.)dingtalk\.com$/, /(^|\.)dingtalkapps\.com$/, /(^|\.)alicdn\.com$/];
const intercept = (host) => INTERCEPT.some((re) => re.test(host));

if (!existsSync(RUN_DIR)) mkdirSync(RUN_DIR, { recursive: true });

let seq = 0;
function record(host, kind, data) {
  const n = String(++seq).padStart(4, '0');
  const f = join(RUN_DIR, `${n}-${host}-${kind}.bin`);
  createWriteStream(f).end(data);
  return f;
}
const log = (...a) => console.log(`[${new Date().toISOString().slice(11, 23)}]`, ...a);

const server = http.createServer((req, res) => {
  res.writeHead(501, { 'content-type': 'text/plain' });
  res.end('teletalk MITM: 仅支持 HTTPS CONNECT');
});

server.on('connect', (req, clientSocket, head) => {
  const [host, portStr] = (req.url || '').split(':');
  const port = Number(portStr || 443);

  if (!intercept(host)) {
    const upstream = net.connect(port, host, () => {
      clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head?.length) upstream.write(head);
      upstream.pipe(clientSocket);
      clientSocket.pipe(upstream);
    });
    upstream.on('error', () => clientSocket.destroy());
    clientSocket.on('error', () => upstream.destroy());
    return;
  }

  log('TLS', host, port);
  clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
  if (head?.length) clientSocket.unshift(head);

  let site;
  try { site = certForHost(host); }
  catch (e) { log('cert error', host, e.message); clientSocket.destroy(); return; }

  // 用 tls.TLSSocket 包装，手动喂数据
  const tlsSocket = new tls.TLSSocket(clientSocket, {
    isServer: true,
    key: site.key,
    cert: site.cert,
    ALPNProtocols: ['http/1.1'],
  });

  tlsSocket.once('secure', () => {
    log('client handshake ok', host, 'alpn=', tlsSocket.alpnProtocol);
    const upstream = tls.connect({ host, port, servername: host, ALPNProtocols: ['http/1.1'] });
    const c2s = [], s2c = [];

    upstream.once('secureConnect', () => {
      log('upstream secure', host);
      upstream.on('data', (c) => { s2c.push(c); tlsSocket.write(c); });
      upstream.on('end', () => { tlsSocket.end(); });
      upstream.on('close', () => {
        if (s2c.length) record(host, 's2c', Buffer.concat(s2c));
        if (c2s.length) record(host, 'c2s', Buffer.concat(c2s));
        log('closed', host, `c2s=${c2s.length}B s2c=${s2c.length}B`);
      });
      upstream.on('error', (e) => { log('upstream err', host, e.message); tlsSocket.destroy(); });
      tlsSocket.on('data', (c) => { c2s.push(c); upstream.write(c); });
      tlsSocket.on('end', () => upstream.end());
      tlsSocket.on('error', (e) => log('client err', host, e.message));
    });
    upstream.on('error', (e) => { log('upstream connect err', host, e.message); tlsSocket.destroy(); });
  });

  tlsSocket.on('error', (e) => log('tls err', host, e.message));
});

server.listen(PORT, () => {
  log(`MITM 代理已启动 :${PORT}`);
  log(`输出目录: ${RUN_DIR}`);
});

process.on('SIGINT', () => { log('关闭'); server.close(); process.exit(0); });
