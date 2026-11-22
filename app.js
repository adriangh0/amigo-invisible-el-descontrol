/* ============================================================
   app.js — Lógica compartida de Amigo Invisible El Descontrol
   ============================================================ */

'use strict';

/* ── Copos de nieve ── */
function crearCopos(n) {
  const contenedor = document.body;
  for (let i = 0; i < n; i++) {
    const copo = document.createElement('div');
    copo.className = 'copo';

    const tamanio   = Math.random() * 5 + 3;        // 3–8 px
    const izquierda = Math.random() * 100;           // 0–100 vw
    const duracion  = Math.random() * 8 + 6;        // 6–14 s
    const retraso   = Math.random() * 10;            // 0–10 s
    const opacidad  = Math.random() * 0.5 + 0.4;    // 0.4–0.9

    copo.style.cssText = `
      width: ${tamanio}px;
      height: ${tamanio}px;
      left: ${izquierda}vw;
      opacity: ${opacidad};
      animation-duration: ${duracion}s;
      animation-delay: -${retraso}s;
    `;

    contenedor.appendChild(copo);
  }
}

/* ── Sesión ── */
function limpiarSesion() {
  sessionStorage.removeItem('amigoInvisible_usuario');
  sessionStorage.removeItem('amigoInvisible_asignado');
  sessionStorage.removeItem('amigoInvisible_asignadoSexo');
  sessionStorage.removeItem('amigoInvisible_asignadoFoto');
  sessionStorage.removeItem('amigoInvisible_revelado');
  sessionStorage.removeItem('amigoInvisible_apuesta');
  sessionStorage.removeItem('amigoInvisible_textoApuesta');
}

/* ── Criptografía (SHA-256 puro en JS, funciona en local file:// y HTTPS) ── */
function normalizarNombre(str) {
  return String(str || '').trim().toLowerCase();
}

function sha256Bytes(asciiBytes) {
  const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];
  const rotr = (n, x) => (x >>> n) | (x << (32 - n));
  const msg = Array.from(asciiBytes);
  const bitLen = msg.length * 8;
  msg.push(0x80);
  while ((msg.length % 64) !== 56) msg.push(0);
  const hi = Math.floor(bitLen / 0x100000000);
  const lo = bitLen >>> 0;
  msg.push((hi >>> 24) & 0xff, (hi >>> 16) & 0xff, (hi >>> 8) & 0xff, hi & 0xff);
  msg.push((lo >>> 24) & 0xff, (lo >>> 16) & 0xff, (lo >>> 8) & 0xff, lo & 0xff);

  let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
  let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;

  const W = new Array(64);
  for (let i = 0; i < msg.length; i += 64) {
    for (let t = 0; t < 16; t++) {
      const j = i + t * 4;
      W[t] = ((msg[j] << 24) | (msg[j + 1] << 16) | (msg[j + 2] << 8) | msg[j + 3]) >>> 0;
    }
    for (let t = 16; t < 64; t++) {
      const s0 = (rotr(7, W[t - 15]) ^ rotr(18, W[t - 15]) ^ (W[t - 15] >>> 3)) >>> 0;
      const s1 = (rotr(17, W[t - 2]) ^ rotr(19, W[t - 2]) ^ (W[t - 2] >>> 10)) >>> 0;
      W[t] = (W[t - 16] + s0 + W[t - 7] + s1) >>> 0;
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
    for (let t = 0; t < 64; t++) {
      const S1 = (rotr(6, e) ^ rotr(11, e) ^ rotr(25, e)) >>> 0;
      const ch = ((e & f) ^ (~e & g)) >>> 0;
      const temp1 = (h + S1 + ch + K[t] + W[t]) >>> 0;
      const S0 = (rotr(2, a) ^ rotr(13, a) ^ rotr(22, a)) >>> 0;
      const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
      const temp2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e; e = (d + temp1) >>> 0;
      d = c; c = b; b = a; a = (temp1 + temp2) >>> 0;
    }
    h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + h) >>> 0;
  }

  const out = [];
  [h0, h1, h2, h3, h4, h5, h6, h7].forEach(w => {
    out.push((w >>> 24) & 0xff, (w >>> 16) & 0xff, (w >>> 8) & 0xff, w & 0xff);
  });
  return out;
}

function bytesToHex(bytes) {
  return bytes.map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex) {
  const out = [];
  for (let i = 0; i < hex.length; i += 2) {
    out.push(parseInt(hex.slice(i, i + 2), 16));
  }
  return out;
}

function sha256Hex(str) {
  const utf8 = new TextEncoder().encode(String(str));
  return bytesToHex(sha256Bytes(utf8));
}

function hashNombre(nombre) {
  return sha256Hex('descontrol:user:' + normalizarNombre(nombre));
}

function hashCredencial(nombre, password) {
  return sha256Hex('descontrol:auth:' + normalizarNombre(nombre) + ':' + String(password));
}

function cifrarConClave(textoPlano, nombre, password) {
  const dataBytes = new TextEncoder().encode(String(textoPlano));
  const keySeed = 'descontrol:key:' + normalizarNombre(nombre) + ':' + String(password);
  const out = [];
  let bloque = 0;
  let keyBytes = [];
  for (let i = 0; i < dataBytes.length; i++) {
    if (i % 32 === 0) {
      keyBytes = sha256Bytes(new TextEncoder().encode(keySeed + ':' + bloque));
      bloque++;
    }
    out.push(dataBytes[i] ^ keyBytes[i % 32]);
  }
  return bytesToHex(out);
}

function descifrarConClave(hexCifrado, nombre, password) {
  const cifradoBytes = hexToBytes(hexCifrado);
  const keySeed = 'descontrol:key:' + normalizarNombre(nombre) + ':' + String(password);
  const out = new Uint8Array(cifradoBytes.length);
  let bloque = 0;
  let keyBytes = [];
  for (let i = 0; i < cifradoBytes.length; i++) {
    if (i % 32 === 0) {
      keyBytes = sha256Bytes(new TextEncoder().encode(keySeed + ':' + bloque));
      bloque++;
    }
    out[i] = cifradoBytes[i] ^ keyBytes[i % 32];
  }
  return new TextDecoder().decode(out);
}

function ofuscarListaPublica(arr) {
  const jsonBytes = new TextEncoder().encode(JSON.stringify(arr));
  const mask = sha256Bytes(new TextEncoder().encode('descontrol:public:mask'));
  const out = [];
  for (let i = 0; i < jsonBytes.length; i++) {
    out.push(jsonBytes[i] ^ mask[i % 32]);
  }
  return bytesToHex(out);
}

function desofuscarListaPublica(hex) {
  if (!hex) return [];
  try {
    const bytes = hexToBytes(hex);
    const mask = sha256Bytes(new TextEncoder().encode('descontrol:public:mask'));
    const out = new Uint8Array(bytes.length);
    for (let i = 0; i < bytes.length; i++) {
      out[i] = bytes[i] ^ mask[i % 32];
    }
    return JSON.parse(new TextDecoder().decode(out));
  } catch {
    return [];
  }
}

/* ── Inicialización común ── */
document.addEventListener('DOMContentLoaded', () => {
  crearCopos(30);
});

