// ============================================================================
// Secure Private Chat — Local development server
// Serves the static app from ./public and attaches the zero-knowledge
// signaling layer (WebSocket). Same signaling core used by the Vercel
// Function in api/ws.js — behavior is identical in both environments.
// ============================================================================

import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { attachSignaling } from './lib/signaling.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 3000;

const MIME_TYPES = {
  '.html': 'text/html',
  '.js': 'application/javascript',
  '.css': 'text/css',
  '.json': 'application/json',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
};

const server = http.createServer((req, res) => {
  const filePath = path.join(__dirname, 'public', req.url === '/' ? 'index.html' : req.url);
  const ext = path.extname(filePath);
  const contentType = MIME_TYPES[ext] || 'application/octet-stream';

  const cacheControl = ext === '.html'
    ? 'public, max-age=0, must-revalidate'
    : 'public, max-age=31536000, immutable';

  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not Found');
      return;
    }
    res.writeHead(200, { 'Content-Type': contentType, 'Cache-Control': cacheControl });
    res.end(data);
  });
});

// Zero-knowledge WebSocket signaling on the same server instance.
attachSignaling(server);

// Intentionally no startup logging — this server knows nothing to log.
server.listen(PORT, () => {});