
const fs = require('fs');
const path = require('path');
const { getFlagSecret, hmacHex } = require('./_runtimeCrypto');

// RFC 4648 Base32 alphabet
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(buf) {
  let bits = 0;
  let value = 0;
  let output = '';
  for (let i = 0; i < buf.length; i++) {
    value = (value << 8) | buf[i];
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      output += BASE32_ALPHABET[(value >>> bits) & 0x1f];
    }
  }
  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 0x1f];
  }
  while (output.length % 8 !== 0) output += '=';
  return output;
}

// XOR-encrypt a UTF-8 string with a repeating 4-byte key derived from the
// first 4 bytes of the HMAC hash, then Base32-encode the result.
//
// Flag format: SDG{<32 hex chars>}  → 37 bytes
// Encrypted:   Base32(XOR(flag, key[0..3] repeating))  → 60 chars + ==== = 64 chars
//
// Key length chosen so that the 4-byte known prefix "SDG{" uniquely recovers
// all key bytes with no ambiguity (no brute-force needed once the prefix is known).
function encryptFlag(flag, fullHashHex) {
  const key = Buffer.from(fullHashHex.slice(0, 8), 'hex'); // first 4 bytes
  const plaintext = Buffer.from(flag, 'utf8');
  const ciphertext = Buffer.alloc(plaintext.length);
  for (let i = 0; i < plaintext.length; i++) {
    ciphertext[i] = plaintext[i] ^ key[i % key.length];
  }
  return base32Encode(ciphertext);
}

function loadTemplate() {
  const templatePath = path.join(__dirname, 'templates', 'audit_logs_template.txt');
  return fs.readFileSync(templatePath, 'utf8');
}

function sendFile(res, content, filename) {
  res.statusCode = 200;
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.setHeader('Cache-Control', 'no-store');
  res.end(content);
}

function json(res, status, body) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(body));
}

module.exports = async function handler(req, res) {
  try {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const seed = url.searchParams.get('seed') || '';
    const action = url.searchParams.get('action') || 'download';

    if (!seed || !/^[0-9a-f]{64}$/i.test(String(seed))) {
      return json(res, 400, { error: 'Missing or invalid seed (expected 64 hex chars)' });
    }

    if (action === 'info') {
      return json(res, 200, {
        ok: true,
        challenge: 'encrypted-audit-logs',
        system: 'ClinCore Health Systems Audit Log Exporter v3.2',
        description: 'Download the audit log archive for forensic analysis. A session token was encrypted and embedded in the log during the storage failover event on 2026-03-17.',
        artifact: {
          filename: 'audit_logs.txt',
          mime_type: 'text/plain',
          size_hint: '~6 KB',
        },
        cipher_note: 'The encryption scheme uses a repeating-key XOR cipher. The key is derived from the session HMAC. Standard cryptanalysis techniques apply.',
        download_url: `?seed=${seed}&action=download`,
      });
    }

    if (action === 'download') {
      const flagSecret = getFlagSecret();
      // Compute the same HMAC body that computeFlag() uses internally
      const fullHashHex = hmacHex(flagSecret, `flag:v2:${seed}:encrypted-audit-logs`);
      const flag = `SDG{${fullHashHex.slice(0, 32)}}`;
      const encryptedToken = encryptFlag(flag, fullHashHex);

      const template = loadTemplate();
      const output = template.replace('{{FLAG_ENC}}', encryptedToken);

      return sendFile(res, output, 'audit_logs.txt');
    }

    return json(res, 400, { error: 'Unknown action. Use: info, download' });
  } catch (e) {
    const msg = (e && typeof e.message === 'string') ? e.message : JSON.stringify(e || 'Unknown error');
    return json(res, 500, { error: msg });
  }
};
