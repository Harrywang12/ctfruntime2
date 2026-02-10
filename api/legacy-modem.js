// Vercel Serverless Function
// SDG 9 Easy: Legacy Modem
// Simulates a legacy modem admin interface that requires Basic Auth.
// The password "infra2030" is hinted in the HTML page (in an HTML comment
// and via a "default credentials" note). The username is "admin".
// Correct auth returns the proof.

const { computeProof } = require('./_runtimeCrypto');

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

        if (!seed || !/^[0-9a-f]{64}$/i.test(String(seed))) {
            return json(res, 400, { error: 'Missing or invalid seed' });
        }

        const proof = computeProof({ artifactSeed: seed, runtimeSlug: 'legacy-modem' });

        // Check Basic Auth header
        const authHeader = req.headers['authorization'] || '';
        if (!authHeader.startsWith('Basic ')) {
            res.statusCode = 401;
            res.setHeader('WWW-Authenticate', 'Basic realm="Legacy Modem Admin"');
            res.setHeader('Content-Type', 'application/json; charset=utf-8');
            res.setHeader('Cache-Control', 'no-store');
            return res.end(JSON.stringify({
                error: 'Authentication required',
                hint: 'This endpoint requires Basic authentication. Check the challenge page for default credentials.',
            }));
        }

        // Decode and verify
        let decoded = '';
        try {
            decoded = Buffer.from(authHeader.slice(6), 'base64').toString('utf8');
        } catch {
            return json(res, 401, { error: 'Malformed Authorization header' });
        }

        const [username, password] = decoded.split(':');

        if (username !== 'admin' || password !== 'infra2030') {
            return json(res, 403, {
                error: 'Invalid credentials',
                hint: 'The default credentials may still be in use. Check the page source carefully.',
            });
        }

        return json(res, 200, {
            ok: true,
            system: 'LegacyModem-9600 Admin Panel',
            message: 'Authentication successful. Diagnostic session active.',
            session: {
                user: 'admin',
                privilege: 'FULL',
                modem_firmware: 'LM-9600-v1.2.3',
                diagnostic_token: proof,
            },
        });
    } catch (e) {
        const msg = (e && typeof e.message === 'string') ? e.message : JSON.stringify(e || 'Unknown error');
        return json(res, 500, { error: msg });
    }
};
