'use strict';
// Zero-dependency structured logger — renkli, component-etiketli, hex-dump destekli.
// DTLS debug'ının %80'i "hangi bayt nereye gitti" seviyesinde olduğu için hex dump 1. sınıf feature.

const LEVELS = { TRACE: 10, DEBUG: 20, INFO: 30, WARN: 40, ERROR: 50 };
const LEVEL_COLORS = {
  TRACE: '\x1b[90m', DEBUG: '\x1b[36m', INFO:  '\x1b[32m',
  WARN:  '\x1b[33m', ERROR: '\x1b[31m',
};
const RESET = '\x1b[0m';
const DIM   = '\x1b[2m';
const BOLD  = '\x1b[1m';

// Kütüphane olarak varsayılan sessizdir; DTLS_LOG_LEVEL ile açılır.
const envLevel = (process.env.DTLS_LOG_LEVEL || 'WARN').toUpperCase();
let minLevel = LEVELS[envLevel] ?? LEVELS.WARN;
const colorEnabled = process.stdout.isTTY && process.env.NO_COLOR !== '1';

function c(code) { return colorEnabled ? code : ''; }

function ts() {
  const d = new Date();
  return d.toISOString().slice(11, 23); // HH:MM:SS.mmm
}

function bufReplacer(_k, v) {
  if (Buffer.isBuffer(v)) {
    const head = v.toString('hex').slice(0, 64);
    return `<Buffer ${v.length}B 0x${head}${v.length > 32 ? '…' : ''}>`;
  }
  return v;
}

function fmt(levelName, component, msg, meta) {
  const color = c(LEVEL_COLORS[levelName] || '');
  const head = `${c(DIM)}${ts()}${c(RESET)} ${color}${c(BOLD)}${levelName.padEnd(5)}${c(RESET)} ${color}[${component}]${c(RESET)} ${msg}`;
  if (meta === undefined) return head;
  if (typeof meta === 'string') return `${head} ${c(DIM)}${meta}${c(RESET)}`;
  try {
    return `${head}\n${c(DIM)}${JSON.stringify(meta, bufReplacer, 2)}${c(RESET)}`;
  } catch {
    return `${head} ${String(meta)}`;
  }
}

function hexDump(buf, { width = 16, indent = '  ' } = {}) {
  if (!Buffer.isBuffer(buf) || buf.length === 0) return `${indent}<empty>`;
  const out = [];
  for (let i = 0; i < buf.length; i += width) {
    const slice = buf.slice(i, i + width);
    const hex = [...slice].map(b => b.toString(16).padStart(2, '0'))
                          .join(' ').padEnd(width * 3 - 1, ' ');
    const ascii = [...slice].map(b => (b >= 0x20 && b < 0x7f)
      ? String.fromCharCode(b) : '.').join('');
    const off = i.toString(16).padStart(6, '0');
    out.push(`${indent}${c(DIM)}${off}${c(RESET)}  ${hex}  ${c(DIM)}|${ascii}|${c(RESET)}`);
  }
  return out.join('\n');
}

function mk(component) {
  const emit = (lvlName, msg, meta) => {
    if (LEVELS[lvlName] < minLevel) return;
    const stream = LEVELS[lvlName] >= LEVELS.WARN ? process.stderr : process.stdout;
    stream.write(fmt(lvlName, component, msg, meta) + '\n');
  };
  return {
    trace: (m, x) => emit('TRACE', m, x),
    debug: (m, x) => emit('DEBUG', m, x),
    info:  (m, x) => emit('INFO',  m, x),
    warn:  (m, x) => emit('WARN',  m, x),
    error: (m, x) => emit('ERROR', m, x),
    hex:   (label, buf) => {
      if (LEVELS.DEBUG < minLevel) return;
      const header = fmt('DEBUG', component, `${label} (${buf?.length ?? 0} bytes)`);
      process.stdout.write(header + '\n' + hexDump(buf) + '\n');
    },
    child: (sub) => mk(`${component}:${sub}`),
  };
}

function setLevel(name) {
  const n = LEVELS[name.toUpperCase()];
  if (n == null) throw new Error(`Unknown log level: ${name}`);
  minLevel = n;
}

module.exports = { mk, hexDump, setLevel, LEVELS };
