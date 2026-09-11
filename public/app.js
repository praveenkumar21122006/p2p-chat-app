/* ============================================================================
 * SECURE PRIVATE CHAT — Client Application
 * ----------------------------------------------------------------------------
 * Section 1 : Cryptography Engine   (PBKDF2 + AES-GCM via WebCrypto)
 * Section 2 : WebRTC Engine         (negotiated DataChannel + STUN + fallback)
 * Section 3 : State Machine / UI    (auth gate -> lobby -> chat screens)
 * ----------------------------------------------------------------------------
 * Zero persistence: nothing is ever written to localStorage, sessionStorage,
 * cookies, or IndexedDB. Keys live only in volatile JS memory.
 * ==========================================================================*/
'use strict';

(function () {
  // ---------------------------------------------------------------------------
  // --------------------------------------------------------------------- Helpers
  // ---------------------------------------------------------------------------

  const $ = (id) => document.getElementById(id);

  const byteEncoder = new TextEncoder();
  const byteDecoder = new TextDecoder();

  /** Uint8Array -> Base64 string */
  function toBase64(bytes) {
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
  }

  /** Base64 string -> Uint8Array */
  function fromBase64(b64) {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }

  // ===========================================================================
  // SECTION 1 — CRYPTOGRAPHY ENGINE (native Web Crypto API only)
  // ===========================================================================

  const KDF_SALT = 'secure-chat-salt-v1';

  /**
   * Derive a 256-bit AES-GCM key from a passphrase using PBKDF2
   * (100,000 iterations, SHA-256) with a static salt string.
   * @param {string} passphrase
   * @param {string} saltString
   * @returns {Promise<CryptoKey>}
   */
  async function deriveKey(passphrase, saltString) {
    const baseKey = await crypto.subtle.importKey(
      'raw',
      byteEncoder.encode(passphrase),
      'PBKDF2',
      false,
      ['deriveKey']
    );

    return crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: byteEncoder.encode(saltString),
        iterations: 100000,
        hash: 'SHA-256',
      },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Encrypt a plaintext string with AES-GCM using a fresh 12-byte IV.
   * Returns { iv, ct } as Base64 strings.
   * @param {CryptoKey} key
   * @param {string} plaintext
   * @returns {Promise<{iv: string, ct: string}>}
   */
  async function encryptMessage(key, plaintext) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      byteEncoder.encode(plaintext)
    );
    return {
      iv: toBase64(iv),
      ct: toBase64(new Uint8Array(ciphertext)),
    };
  }

  /**
   * Decrypt an { iv, ct } object back into a plaintext string.
   * Returns null on any failure without throwing.
   * @param {CryptoKey} key
   * @param {{iv: string, ct: string}} encryptedObj
   * @returns {Promise<string|null>}
   */
  async function decryptMessage(key, encryptedObj) {
    try {
      const iv = fromBase64(encryptedObj.iv);
      const ct = fromBase64(encryptedObj.ct);
      const plaintext = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        key,
        ct
      );
      return byteDecoder.decode(plaintext);
    } catch {
      // Authentication failed, malformed payload, or wrong key — never crash.
      return null;
    }
  }

  // ===========================================================================
  // SECTION 2 — WEBRTC CONNECTION ENGINE
  // ===========================================================================

  const RTC_CONFIG = {
    iceServers: [
      { urls: 'stun:stun.l.google.com:19302' },
      { urls: 'stun:stun.cloudflare.com:3478' },
    ],
  };

  let pc = null;             // RTCPeerConnection
  let dc = null;             // RTCDataChannel "secure-chat"
  let isInitiator = false;   // first joiner of the room
  let channelOpen = false;   // true when the data channel is usable
  let relayMode = false;     // true when encrypted relay fallback is active
  let webrtcStarted = false; // guards duplicate setup
  let pendingCandidates = []; // ICE candidates buffered until remote SDP lands
  let relayWatchdog = null;  // P2P time-out timer

  /**
   * Whether messages are currently transmittable through any transport.
   */
  function hasTransport() {
    return dc && dc.readyState === 'open' && !relayMode;
  }

  /** Buffer ICE candidates received before remoteDescription is set. */
  async function handleRemoteCandidate(candidate) {
    if (!pc || !candidate) return;
    if (!pc.currentRemoteDescription) {
      pendingCandidates.push(candidate);
      return;
    }
    try {
      await pc.addIceCandidate(candidate);
    } catch {
      // Swallow transient ICE errors — retries happen naturally.
    }
  }

  /** Apply any ICE candidates that arrived before the remote SDP. */
  function flushPendingCandidates() {
    while (pendingCandidates.length && pc) {
      pc.addIceCandidate(pendingCandidates.shift()).catch(() => {});
    }
  }

  /** Optionally-used high-Ethernet fallback: renegotiate if possible. */
  function setupIceWire() {
    if (!pc) return;
    pc.onicecandidate = (e) => {
      if (e.candidate && ws && ws.readyState === 1) {
        ws.send(JSON.stringify({ type: 'candidate', candidate: e.candidate }));
      }
    };
  }

  /**
   * Switch to encrypted relay transport when direct P2P is unavailable.
   * All payloads remain AES-GCM encrypted end-to-end.
   */
  function enableRelay() {
    if (relayMode) return;
    relayMode = true;
    clearTimeout(relayWatchdog);
    setCheck('icon-tunnel', 'check-tunnel', 'done');
    if (dc) {
      try { dc.close(); } catch {}
    }
    if (connStatus) {
      connStatus.textContent = 'Relay Mode — Encrypted & Private';
      connStatus.className = 'text-[11px] text-amber-400';
    }
    appendSystem('Direct P2P blocked — switched to encrypted relay.');
  }

  /**
   * Build the peer connection and the negotiated bidirectional data channel.
   * Both sides bind to channel id 0 so no handshake is required.
   */
  async function beginWebRTC() {
    if (webrtcStarted) return;
    webrtcStarted = true;

    pc = new RTCPeerConnection(RTC_CONFIG);
    setupIceWire();

    // ---- Negotiated channel: both peers create it with id 0 -------------
    dc = pc.createDataChannel('secure-chat', { negotiated: true, id: 0 });

    dc.addEventListener('open', () => {
      channelOpen = true;
      clearTimeout(relayWatchdog);
      setCheck('icon-tunnel', 'check-tunnel', 'done');
      showScreen('chat');
      if (connStatus) {
        connStatus.textContent = 'Direct & Secure Connection Established';
        connStatus.className = 'text-[11px] text-emerald-400';
      }
      flushPendingCandidates();
    });

    dc.addEventListener('message', async (e) => {
      try {
        const envelope = JSON.parse(e.data);
        if (envelope.type === 'data') await handleIncoming(envelope.payload);
      } catch {
        // Ignore malformed channel frames.
      }
    });

    dc.addEventListener('close', () => {
      channelOpen = false;
      enableRelay();
    });

    dc.addEventListener('error', () => {
      channelOpen = false;
      enableRelay();
    });

    // ---- Connection-level monitoring for graceful relay fallback ---------
    pc.addEventListener('connectionstatechange', () => {
      if (pc.connectionState === 'failed' && ws && ws.readyState === 1) {
        enableRelay();
      }
    });

    // ---- Time out P2P establishment; fall back to relay ------------------
    relayWatchdog = setTimeout(() => {
      if (!channelOpen) enableRelay();
    }, 12000);

    // ---- Initiator drives the offer/answer flow ---------------------------
    try {
      if (isInitiator) {
        const offer = await pc.createOffer();
        await pc.setLocalDescription(offer);
        ws && ws.send(JSON.stringify({ type: 'offer', offer: offer.sdp }));
      }
    } catch {
      enableRelay();
    }
  }

  // ===========================================================================
  // SECTION 3 — STATE MACHINE & UI ORCHESTRATION
  // ===========================================================================

  const SCREENS = { auth: $('screen-auth'), lobby: $('screen-lobby'), chat: $('screen-chat') };

  const authForm = $('auth-form');
  const roomInput = $('room-input');
  const nameInput = $('name-input');
  const passInput = $('pass-input');
  const authSubmit = $('auth-submit');
  const cancelBtn = $('cancel-btn');
  const panicBtn = $('panic-btn');
  const lobbyRoomId = $('lobby-room-id');
  const chatRoomId = $('chat-room-id');
  const chatWindow = $('chat-window');
  const chatInput = $('chat-input');
  const connStatus = $('conn-status');

  // ---- Volatile session state (never persisted) ----------------------------
  let ws = null;
  let sessionKey = null;
  let myName = '';
  let roomId = '';
  let joined = false;
  let keepAliveTimer = null;

  /** Display a single screen (swaps CSS hidden classes). */
  function showScreen(name) {
    for (const key of Object.keys(SCREENS)) {
      SCREENS[key].classList.toggle('hidden', key !== name);
    }
  }

  /** Set a connection-checklist row state. */
  function setCheck(iconId, itemId, state) {
    const icon = $(iconId);
    const item = $(itemId);
    if (!icon || !item) return;

    while (icon.firstChild) icon.removeChild(icon.firstChild);
    icon.className = 'w-5 h-5 rounded-full shrink-0 flex items-center justify-center ' +
      'text-[10px] font-bold leading-none transition';

    item.classList.remove('text-zinc-100', 'text-zinc-400', 'text-zinc-300', 'text-indigo-300');
    item.classList.add('text-zinc-400');

    if (state === 'done') {
      icon.classList.add('bg-emerald-500');
      icon.appendChild(document.createTextNode('✓'));
      item.classList.remove('text-zinc-400');
      item.classList.add('text-zinc-100');
    } else if (state === 'active') {
      icon.classList.add('border-2', 'border-indigo-400', 'animate-pulse');
      item.classList.remove('text-zinc-400');
      item.classList.add('text-indigo-300');
    } else {
      icon.classList.add('border-2', 'border-zinc-600');
    }
  }

  /** Centered system pill, injected structurally (XSS-safe). */
  function appendSystem(text) {
    const wrap = document.createElement('div');
    wrap.className = 'flex justify-center py-1';
    const pill = document.createElement('span');
    pill.className = 'text-[11px] text-zinc-400 bg-zinc-800/70 border border-zinc-700 rounded-full px-3 py-1';
    pill.appendChild(document.createTextNode(text));
    wrap.appendChild(pill);
    chatWindow.appendChild(wrap);
    chatWindow.scrollTop = chatWindow.scrollHeight;
  }

  /**
   * Render a decrypted message bubble using only structural DOM methods.
   * Never uses innerHTML, so decrypted content can't inject markup.
   */
  function appendMessage({ name, text, ts, out }) {
    const wrap = document.createElement('div');
    wrap.className = 'flex fade-up ' + (out ? 'justify-end' : 'justify-start');

    const bubble = document.createElement('div');
    bubble.className = 'max-w-[75%] rounded-2xl px-4 py-2.5 ' +
      (out ? 'bg-indigo-600 text-white rounded-br-sm' : 'bg-slate-700 text-zinc-100 rounded-bl-sm');

    const meta = document.createElement('div');
    meta.className = 'text-[11px] mb-1 font-medium ' + (out ? 'text-indigo-200' : 'text-zinc-400');
    meta.appendChild(document.createTextNode(name));

    const textEl = document.createElement('p');
    textEl.className = 'text-sm break-words whitespace-pre-wrap';
    textEl.appendChild(document.createTextNode(text));

    const timeEl = document.createElement('div');
    timeEl.className = 'text-[10px] mt-1 ' + (out ? 'text-indigo-200/70' : 'text-zinc-500');
    timeEl.appendChild(document.createTextNode(fmtTime(ts)));

    bubble.appendChild(meta);
    bubble.appendChild(textEl);
    bubble.appendChild(timeEl);
    wrap.appendChild(bubble);
    chatWindow.appendChild(wrap);

    chatWindow.scrollTop = chatWindow.scrollHeight;
  }

  /** Format a unix timestamp as HH:MM. */
  function fmtTime(ts) {
    return new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }

  /**
   * Incoming transport payload handler: decrypt + parse + render.
   */
  async function handleIncoming(encryptedObj) {
    if (!sessionKey) return;
    const plain = await decryptMessage(sessionKey, encryptedObj);
    if (plain === null) return; // auth failure or bad payload — silently drop
    try {
      const msg = JSON.parse(plain);
      if (msg && msg.t !== undefined) {
        showScreen('chat');
        appendMessage({ name: msg.n || 'Peer', text: msg.t, ts: msg.s || Date.now(), out: false });
      }
    } catch {
      // Corrupt decryption payload — ignore.
    }
  }

  /** Compose, encrypt, and transmit a chat message on the active transport. */
  async function sendMessage(text) {
    if (!sessionKey || !text) return;

    const payload = { n: myName, t: text, s: Date.now() };

    try {
      const encrypted = await encryptMessage(sessionKey, JSON.stringify(payload));

      if (hasTransport()) {
        dc.send(JSON.stringify({ type: 'data', payload: encrypted }));
      } else if (ws && ws.readyState === 1 && relayMode) {
        ws.send(JSON.stringify({ type: 'relay', payload: encrypted }));
      } else {
        return; // no viable transport yet
      }

      appendMessage({ name: myName, text, ts: payload.s, out: true });
    } catch {
      // Encryption or send failure — message never leaves the device.
    }
  }

  /** Soft teardown: close transports and drop volatile keys from memory. */
  function teardown() {
    clearTimeout(relayWatchdog);
    clearInterval(keepAliveTimer);
    keepAliveTimer = null;
    joined = false;
    channelOpen = false;
    relayMode = false;
    webrtcStarted = false;
    isInitiator = false;
    pendingCandidates = [];
    sessionKey = null;
    if (dc) { try { dc.close(); } catch {} dc = null; }
    if (pc) { try { pc.close(); } catch {} pc = null; }
    if (ws) { ws.onmessage = ws.onopen = ws.onclose = ws.onerror = null; try { ws.close(); } catch {} ws = null; }
    while (chatWindow.firstChild) chatWindow.removeChild(chatWindow.firstChild);
  }

  // ---------------------------------------------------------------------------
  // Screen 1 — Auth Gate
  // ---------------------------------------------------------------------------

  authForm.addEventListener('submit', async (e) => {
    e.preventDefault();

    const room = roomInput.value.trim();
    const name = nameInput.value.trim();
    const pass = passInput.value;

    if (!room || !name || !pass) return;

    roomId = room;
    myName = name;
    lobbyRoomId.textContent = room;
    chatRoomId.textContent = room;

    try {
      if (!crypto.subtle) throw new Error('WebCrypto unavailable');
      sessionKey = await deriveKey(pass, KDF_SALT);
    } catch {
      appendSystem('WebCrypto not available in this browser.');
      return;
    }

    showScreen('lobby');
    setCheck('icon-signal', 'check-signal', 'active');

    // The signaling endpoint lives at /api/ws in both environments.
    const proto = location.protocol === 'https:' ? 'wss://' : 'ws://';
    ws = new WebSocket(proto + location.host + '/api/ws');
    ws.addEventListener('open', () => {
      ws.send(JSON.stringify({ type: 'join', roomId }));
    });
    ws.addEventListener('message', handleServerMessage);
    ws.addEventListener('close', () => {
      if (joined) {
        appendSystem('Connection to signaling server lost.');
      }
    });
    ws.addEventListener('error', () => {
      setCheck('icon-signal', 'check-signal', 'done');
      // Server unreachable — the close event surfaces the failure.
    });
  });

  /** Send periodic pings so the signaling connection is never idled out. */
  function startKeepAlive() {
    clearInterval(keepAliveTimer);
    keepAliveTimer = setInterval(() => {
      if (ws && ws.readyState === 1) {
        ws.send(JSON.stringify({ type: 'ping' }));
      }
    }, 45000);
  }

  /**
   * Server message dispatcher (blind-relay signaling + relay fallback traffic).
   */
  function handleServerMessage(e) {
    let msg;
    try {
      msg = JSON.parse(e.data);
    } catch {
      return;
    }

    switch (msg.type) {
      case 'error':
        // Room occupied — leave the lobby and return to the gate.
        setCheck('icon-signal', 'check-signal', 'done');
        appendSystem(msg.message === 'Room Full' ? 'This room is already full.' : msg.message);
        teardown();
        showScreen('auth');
        break;

      case 'joined':
        joined = true;
        isInitiator = msg.peerCount === 1;
        setCheck('icon-signal', 'check-signal', 'done');
        setCheck('icon-peer', 'check-peer', 'active');
        startKeepAlive();
        break;

      case 'ready':
        // Both peers present — negotiate the tunnel.
        setCheck('icon-peer', 'check-peer', 'done');
        setCheck('icon-tunnel', 'check-tunnel', 'active');
        beginWebRTC();
        break;

      case 'offer':
        setCheck('icon-tunnel', 'check-tunnel', 'active');
        (async () => {
          try {
            if (!pc) beginWebRTC();
            await pc.setRemoteDescription({ type: 'offer', sdp: msg.offer });
            flushPendingCandidates();
            const answer = await pc.createAnswer();
            await pc.setLocalDescription(answer);
            ws && ws.send(JSON.stringify({ type: 'answer', answer: answer.sdp }));
          } catch {
            enableRelay();
          }
        })();
        break;

      case 'answer':
        (async () => {
          try {
            await pc.setRemoteDescription({ type: 'answer', sdp: msg.answer });
            flushPendingCandidates();
          } catch {
            enableRelay();
          }
        })();
        break;

      case 'candidate':
        handleRemoteCandidate(msg.candidate);
        break;

      case 'relay':
        // Encrypted fallback traffic — decrypt like any channel payload.
        handleIncoming(msg.payload);
        break;

      case 'peer-disconnected':
        appendSystem('Your peer left the session.');
        break;
    }
  }

  // ---------------------------------------------------------------------------
  // Screen 2 — Lobby controls
  // ---------------------------------------------------------------------------

  cancelBtn.addEventListener('click', () => {
    teardown();
    showScreen('auth');
    roomInput.value = '';
    nameInput.value = '';
    passInput.value = '';
  });

  // ---------------------------------------------------------------------------
  // Screen 3 — Chat interface
  // ---------------------------------------------------------------------------

  panicBtn.addEventListener('click', () => {
    // Hard wipe: reload destroys every key, channel, and object in memory.
    window.location.reload();
  });

  chatInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      const text = chatInput.value;
      if (text.trim()) {
        sendMessage(text.trim());
        chatInput.value = '';
        chatInput.style.height = 'auto';
      }
    }
  });

  chatInput.addEventListener('input', () => {
    chatInput.style.height = 'auto';
    chatInput.style.height = Math.min(chatInput.scrollHeight, 128) + 'px';
  });

  // Guard against double-submit on the auth button.
  authSubmit.addEventListener('click', () => {
    setTimeout(() => (authSubmit.disabled = true), 0);
    setTimeout(() => (authSubmit.disabled = false), 500);
  });
})();