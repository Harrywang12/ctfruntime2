// Vercel Serverless Function
// SDG 9 Hard: Chemical Plant
// Multi-layered challenge:
// 1. GET ?action=status returns an "encrypted" status string (XOR with a rolling key)
//    AND a plaintext version. Player can XOR them to recover the key.
// 2. Player must then encrypt the command "EMERGENCY_DUMP" with the same rolling key
//    and send it via POST ?action=command&payload=<hex>.
// 3. The key is derived from the seed, so it's deterministic per team.
// 4. Additional layer: the key rotates every 4 bytes using a simple LFSR-like step,
//    so players must figure out the rotation pattern.

const { computeProof } = require('./_runtimeCrypto');

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

function json(res, status, body) {
    res.statusCode = status;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    res.end(JSON.stringify(body));
}

// Derive a rolling key from the seed
function deriveKeyStream(seed, length) {
    const keyBytes = [];
    let state = simpleHash(seed, 'chemkey');
    for (let i = 0; i < length; i++) {
        // LFSR-like step: every 4 bytes, mutate the state
        if (i > 0 && i % 4 === 0) {
            state = ((state * 1103515245 + 12345) >>> 0) & 0xFFFFFFFF;
        }
        keyBytes.push((state >>> ((i % 4) * 8)) & 0xFF);
    }
    return keyBytes;
}

function xorEncrypt(plaintext, keyStream) {
    const result = [];
    for (let i = 0; i < plaintext.length; i++) {
        result.push(plaintext.charCodeAt(i) ^ keyStream[i % keyStream.length]);
    }
    return Buffer.from(result).toString('hex');
}

function xorDecryptHex(hexStr, keyStream) {
    const bytes = Buffer.from(hexStr, 'hex');
    const result = [];
    for (let i = 0; i < bytes.length; i++) {
        result.push(bytes[i] ^ keyStream[i % keyStream.length]);
    }
    return Buffer.from(result).toString('utf8');
}

function readBody(req) {
    return new Promise((resolve, reject) => {
        let data = '';
        req.on('data', (chunk) => { data += chunk; });
        req.on('end', () => {
            try {
                resolve(data ? JSON.parse(data) : {});
            } catch {
                resolve({});
            }
        });
        req.on('error', reject);
    });
}

module.exports = async function handler(req, res) {
    try {
        const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
        const seed = url.searchParams.get('seed') || '';
        const action = url.searchParams.get('action') || 'status';

        if (!seed || !/^[0-9a-f]{64}$/i.test(String(seed))) {
            return json(res, 400, { error: 'Missing or invalid seed' });
        }

        const proof = computeProof({ artifactSeed: seed, runtimeSlug: 'chemical-plant' });
        const TARGET_COMMAND = 'EMERGENCY_DUMP';

        if (action === 'status') {
            // Known plaintext: "REACTOR_NOMINAL" (15 chars)
            const knownPlain = 'REACTOR_NOMINAL';
            const keyStream = deriveKeyStream(seed, knownPlain.length);
            const encrypted = xorEncrypt(knownPlain, keyStream);

            return json(res, 200, {
                ok: true,
                system: 'ChemPlant-9 SCADA Interface',
                reactor_status: 'nominal',
                encrypted_status: encrypted,
                plaintext_status: knownPlain,
                command_format: {
                    method: 'POST',
                    query: '?seed=<seed>&action=command',
                    body: '{ "payload": "<hex-encoded encrypted command>" }',
                    target: 'Encrypt the correct emergency command to obtain diagnostic access.',
                },
                hints: [
                    'The encrypted_status was produced by XOR-ing plaintext_status with a key stream.',
                    'XOR is its own inverse: plaintext XOR encrypted = key stream.',
                    'The key stream uses a rolling pattern that mutates every 4 bytes.',
                    'The target command is longer than the sample. Figure out how the key extends.',
                ],
            });
        }

        if (action === 'keyhint') {
            // Additional hint: show a second known-plaintext pair with a longer string
            const knownPlain2 = 'SYSTEM_CHECK_OK_';
            const keyStream2 = deriveKeyStream(seed, knownPlain2.length);
            const encrypted2 = xorEncrypt(knownPlain2, keyStream2);

            return json(res, 200, {
                ok: true,
                second_sample: {
                    encrypted: encrypted2,
                    plaintext: knownPlain2,
                    note: 'Same key stream is used. This 16-char sample reveals the LFSR rotation at byte 4.',
                },
            });
        }

        if (action === 'command') {
            if (req.method !== 'POST') {
                return json(res, 405, { error: 'Command action requires POST method' });
            }

            const body = await readBody(req);
            const payload = (body.payload || '').trim().toLowerCase();

            if (!payload) {
                return json(res, 400, { error: 'Missing payload in request body' });
            }

            if (!/^[0-9a-f]+$/.test(payload)) {
                return json(res, 400, { error: 'Payload must be hex-encoded' });
            }

            const targetKeyStream = deriveKeyStream(seed, TARGET_COMMAND.length);
            const expectedPayload = xorEncrypt(TARGET_COMMAND, targetKeyStream);

            if (payload !== expectedPayload) {
                // Give a hint about which bytes are wrong
                const payloadBytes = Buffer.from(payload, 'hex');
                const expectedBytes = Buffer.from(expectedPayload, 'hex');
                let firstWrongByte = -1;
                for (let i = 0; i < Math.min(payloadBytes.length, expectedBytes.length); i++) {
                    if (payloadBytes[i] !== expectedBytes[i]) {
                        firstWrongByte = i;
                        break;
                    }
                }

                return json(res, 403, {
                    error: 'Command rejected: decryption produced an invalid command string.',
                    payload_length: payloadBytes.length,
                    expected_length: TARGET_COMMAND.length,
                    first_mismatch_byte: firstWrongByte,
                    hint: 'Make sure you understand how the key stream rolls every 4 bytes.',
                });
            }

            return json(res, 200, {
                ok: true,
                message: 'EMERGENCY_DUMP authorized. Diagnostic core dump follows.',
                diagnostic_dump: {
                    reactor_id: 'RX-' + seed.slice(0, 8).toUpperCase(),
                    core_temp_c: 847.2,
                    pressure_mpa: 15.3,
                    override_token: proof,
                    alert_level: 'CRITICAL',
                },
            });
        }

        return json(res, 400, { error: 'Unknown action. Use status, keyhint, or command.' });
    } catch (e) {
        const msg = (e && typeof e.message === 'string') ? e.message : JSON.stringify(e || 'Unknown error');
        return json(res, 500, { error: msg });
    }
};
