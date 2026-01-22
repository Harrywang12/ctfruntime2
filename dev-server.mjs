import http from 'node:http';
import { createReadStream, existsSync, statSync } from 'node:fs';
import { extname, join, normalize } from 'node:path';

const port = Number(process.env.PORT || 3000);
const rootDir = process.cwd();

const contentTypeByExt = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.svg': 'image/svg+xml; charset=utf-8',
  '.txt': 'text/plain; charset=utf-8',
  '.ico': 'image/x-icon'
};

function safeResolvePath(urlPath) {
  const decodedPath = decodeURIComponent(urlPath.split('?')[0] ?? '/');
  const stripped = decodedPath.replace(/^\/+/, '');
  const normalized = normalize(stripped);
  if (normalized.startsWith('..')) return null;
  return join(rootDir, normalized);
}

function sendFile(res, filePath) {
  const ext = extname(filePath).toLowerCase();
  res.statusCode = 200;
  res.setHeader('Content-Type', contentTypeByExt[ext] ?? 'application/octet-stream');
  createReadStream(filePath).pipe(res);
}

function sendIndex(res) {
  const indexPath = join(rootDir, 'index.html');
  if (!existsSync(indexPath)) {
    res.statusCode = 404;
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.end('index.html not found');
    return;
  }
  sendFile(res, indexPath);
}

const server = http.createServer((req, res) => {
  try {
    const method = req.method ?? 'GET';
    const url = req.url ?? '/';

    if (method !== 'GET' && method !== 'HEAD') {
      res.statusCode = 405;
      res.setHeader('Content-Type', 'text/plain; charset=utf-8');
      res.end('Method Not Allowed');
      return;
    }

    // Match your vercel.json rewrite: /r/* -> /index.html
    if (url.startsWith('/r/')) {
      sendIndex(res);
      return;
    }

    // Serve static files from project root or /public
    if (url === '/' || url === '/index.html') {
      sendIndex(res);
      return;
    }

    const candidatePaths = [];

    const resolved = safeResolvePath(url);
    if (resolved) candidatePaths.push(resolved);

    const publicResolved = safeResolvePath('/public' + url);
    if (publicResolved) candidatePaths.push(publicResolved);

    for (const filePath of candidatePaths) {
      if (!existsSync(filePath)) continue;
      const st = statSync(filePath);
      if (!st.isFile()) continue;
      sendFile(res, filePath);
      return;
    }

    res.statusCode = 404;
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.end('Not Found');
  } catch (err) {
    res.statusCode = 500;
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.end(String(err));
  }
});

server.listen(port, '0.0.0.0', () => {
  // eslint-disable-next-line no-console
  console.log(`Static dev server listening on http://localhost:${port}`);
});
