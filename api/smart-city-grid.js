

const crypto = require('crypto');
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

function md5(data) {
    return crypto.createHash('md5').update(String(data), 'utf8').digest('hex');
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
        const action = url.searchParams.get('action') || 'status';

        if (!seed || !/^[0-9a-f]{64}$/i.test(String(seed))) {
            return json(res, 400, { error: 'Missing or invalid seed' });
        }

        const proof = computeProof({ artifactSeed: seed, runtimeSlug: 'smart-city-grid' });

        // Derive a per-team 8-char hex secret from the seed
        const secretFull = seed.slice(0, 8);

        // Current server "timestamp" (deterministic from seed for reproducibility)
        const serverTimestamp = String(1700000000 + simpleHash(seed, 'ts') % 100000);

        if (action === 'debug') {
            // Debug endpoint: leaks timestamp and partial secret
            return json(res, 200, {
                ok: true,
                debug: {
                    server_timestamp: serverTimestamp,
                    partial_secret: secretFull.slice(0, 6) + '**',
                    signature_algorithm: 'md5(timestamp + secret)',
                    note: 'Debug mode enabled for development. Partial secret shown for testing.',
                },
                hint: 'The secret is 8 hex characters. You have 6. Brute-force the remaining 2.',
            });
        }

        if (action === 'authenticate') {
            const clientSig = (url.searchParams.get('signature') || '').trim().toLowerCase();

            if (!clientSig) {
                return json(res, 400, {
                    error: 'Missing signature parameter',
                    hint: 'Provide ?action=authenticate&signature=<md5_hash>. Use ?action=debug for more info.',
                });
            }

            const expectedSig = md5(serverTimestamp + secretFull);

            if (clientSig !== expectedSig) {
                return json(res, 403, {
                    error: 'Signature verification failed',
                    expected_length: 32,
                    hint: 'Signature is md5(timestamp + secret). Use the debug endpoint to get the timestamp and partial secret.',
                });
            }

            return json(res, 200, {
                ok: true,
                message: 'Signature verified. Grid control access granted.',
                grid_control: {
                    access_level: 'ENGINEER',
                    grid_token: proof,
                    sectors_unlocked: ['power', 'water', 'transport'],
                },
            });
        }

        // Default: status
        return json(res, 200, {
            ok: true,
            system: 'Smart City Grid Controller v3.1',
            grid_status: 'nominal',
            sectors: {
                power: { load_pct: 67, status: 'green' },
                water: { flow_rate: 1240, status: 'green' },
                transport: { active_routes: 42, status: 'yellow' },
            },
            actions_available: ['status', 'debug', 'authenticate'],
            hint: 'Grid control requires authentication via a signed request. Try ?action=debug first.',
        });
    } catch (e) {
        const msg = (e && typeof e.message === 'string') ? e.message : JSON.stringify(e || 'Unknown error');
        return json(res, 500, { error: msg });
    }
};
