
const { computeProof } = require('./_runtimeCrypto');

function json(res, status, body) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(body));
}

function simpleHash(seed, salt) {
  const str = String(seed) + String(salt);
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  return Math.abs(hash);
}

function deriveKey(seed) {
  const key = [];
  for (let i = 0; i < 16; i++) {
    key.push(simpleHash(seed, `xor_key:${i}`) & 0xFF);
  }
  return key;
}

function xorHex(inputHex, key) {
  const bytes = Buffer.from(inputHex, 'hex');
  const result = Buffer.alloc(bytes.length);
  for (let i = 0; i < bytes.length; i++) {
    result[i] = bytes[i] ^ key[i % key.length];
  }
  return result.toString('hex');
}

module.exports = async function handler(req, res) {
  try {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const seed = url.searchParams.get('seed') || '';
    const action = url.searchParams.get('action') || 'info';

    if (!seed || !/^[0-9a-f]{64}$/i.test(String(seed))) {
      return json(res, 400, { error: 'Missing or invalid seed' });
    }

    const proof = computeProof({ artifactSeed: seed, runtimeSlug: 'pharmacy-xor-oracle' });
    const key = deriveKey(seed);

    if (action === 'info') {
      const proofHex = Buffer.from(proof, 'ascii').toString('hex');
      const encryptedCode = xorHex(proofHex, key);
      return json(res, 200, {
        ok: true,
        system: 'RxSecure Pharmacy Authorization System v2.0',
        description: 'Encrypted authorization codes are required for controlled substance dispensing.',
        encrypted_prescription_code: encryptedCode,
        key_length_bytes: 16,
        encryption: 'Proprietary repeating-key XOR cipher. Vendor decryption tool required.',
        hint: 'An encryption oracle is available for authorized system testing.',
        actions_available: ['info', 'encrypt'],
      });
    }

    if (action === 'encrypt') {
      const plaintext = (url.searchParams.get('plaintext') || '').toLowerCase();
      if (!plaintext) {
        return json(res, 400, { error: 'Provide ?plaintext=<hex-encoded bytes> to encrypt.' });
      }
      if (!/^[0-9a-f]+$/i.test(plaintext) || plaintext.length % 2 !== 0) {
        return json(res, 400, { error: 'plaintext must be an even-length hex string.' });
      }
      const ciphertext = xorHex(plaintext, key);
      return json(res, 200, {
        ok: true,
        plaintext,
        ciphertext,
        note: 'XOR cipher applied with the system key.',
      });
    }

    return json(res, 400, { error: 'Unknown action. Use: info, encrypt' });
  } catch (e) {
    const msg = (e && typeof e.message === 'string') ? e.message : JSON.stringify(e || 'Unknown error');
    return json(res, 500, { error: msg });
  }
};
