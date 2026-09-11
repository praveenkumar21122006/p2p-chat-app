// ============================================================================
// Vercel Function — Zero-Knowledge Signaling Endpoint
// Runs on Fluid Compute. WebSocket upgrades hit this route (/api/ws), get
// upgraded with the `ws` library, and are served by the shared signaling core
// in ../lib/signaling.js. Static assets are served by Vercel's edge network.
// ============================================================================

import http from 'node:http';
import { attachSignaling } from '../lib/signaling.js';

// No request handler needed: this route only serves WebSocket upgrades.
const server = http.createServer();

attachSignaling(server);

export default server;