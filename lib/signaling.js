// ============================================================================
// Zero-Knowledge Signaling Core  (shared by local server.js and the Vercel
// Function in api/ws.js). No content inspection, no logging of IPs, SDPs, or
// room details. Pure blind forwarding between the two peers of a room.
// ============================================================================

import { WebSocketServer } from 'ws';

const MAX_ROOM_SIZE = 2;

/**
 * Attach the signaling layer to an existing HTTP server.
 * @param {import('http').Server} server
 * @returns {WebSocketServer}
 */
export function attachSignaling(server) {
  // In-memory room map: roomId -> Set<WebSocket>
  const rooms = new Map();

  const wss = new WebSocketServer({ server });

  wss.on('connection', (ws) => {
    let joinedRoom = null;

    ws.on('message', (raw) => {
      let msg;
      try {
        msg = JSON.parse(raw);
      } catch {
        return; // Ignore malformed frames
      }

      // ----------------------------------------------------------------
      // JOIN: Client requests to enter a room
      // ----------------------------------------------------------------
      if (msg.type === 'join') {
        const roomId = msg.roomId;
        if (!roomId || typeof roomId !== 'string') return;

        if (!rooms.has(roomId)) rooms.set(roomId, new Set());
        const room = rooms.get(roomId);

        if (room.size >= MAX_ROOM_SIZE) {
          ws.send(JSON.stringify({ type: 'error', message: 'Room Full' }));
          ws.close();
          return;
        }

        room.add(ws);
        joinedRoom = roomId;

        ws.send(JSON.stringify({ type: 'joined', roomId, peerCount: room.size }));

        // Both peers present — tell each to begin signaling
        if (room.size === 2) {
          for (const client of room) {
            if (client.readyState === 1) {
              client.send(JSON.stringify({ type: 'ready' }));
            }
          }
        }
        return;
      }

      // ----------------------------------------------------------------
      // Keepalive: reply to client pings so free-tier hosts never spin the
      // instance down while a caller sits in the room lobby.
      // ----------------------------------------------------------------
      if (msg.type === 'ping') {
        ws.send(JSON.stringify({ type: 'pong' }));
        return;
      }

      // ----------------------------------------------------------------
      // Blind relay: offer, answer, candidate, relay (encrypted fallback)
      // Forward the message verbatim to the other peer in the room.
      // ----------------------------------------------------------------
      if (['offer', 'answer', 'candidate', 'relay'].includes(msg.type)) {
        if (!joinedRoom) return;
        const room = rooms.get(joinedRoom);
        if (!room) return;

        for (const client of room) {
          if (client !== ws && client.readyState === 1) {
            client.send(JSON.stringify(msg));
          }
        }
      }
    });

    // ----------------------------------------------------------------
    // Cleanup on disconnect: remove from room, delete room if empty
    // ----------------------------------------------------------------
    ws.on('close', () => {
      if (!joinedRoom) return;
      const room = rooms.get(joinedRoom);
      if (!room) return;

      room.delete(ws);

      for (const client of room) {
        if (client.readyState === 1) {
          client.send(JSON.stringify({ type: 'peer-disconnected' }));
        }
      }

      if (room.size === 0) rooms.delete(joinedRoom);
      joinedRoom = null;
    });

    ws.on('error', () => {
      // Silently handled — cleanup happens in 'close'
    });
  });

  return wss;
}