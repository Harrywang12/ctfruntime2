
const { computeProof } = require('./_runtimeCrypto');

function json(res, status, body) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(body));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (chunk) => { data += chunk; });
    req.on('end', () => {
      try { resolve(data ? JSON.parse(data) : {}); } catch { resolve({}); }
    });
    req.on('error', reject);
  });
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

function deriveSessionToken(seed) {
  let result = '';
  for (let i = 0; i < 4; i++) {
    const hash = simpleHash(seed, `vcc_session:${i}`);
    result += (hash & 0xffffff).toString(16).padStart(6, '0');
  }
  return result.slice(0, 24);
}

module.exports = async function handler(req, res) {
  try {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const seed = url.searchParams.get('seed') || '';
    const action = url.searchParams.get('action') || '';

    if (!seed || !/^[0-9a-f]{64}$/i.test(String(seed))) {
      return json(res, 400, { error: 'Missing or invalid seed' });
    }

    const proof = computeProof({ artifactSeed: seed, runtimeSlug: 'vaccine-cold-chain' });
    const sessionToken = deriveSessionToken(seed);

    // Step 1: GET ?action=status — returns sensor readings and a session token
    if (req.method === 'GET' && action === 'status') {
      return json(res, 200, {
        ok: true,
        system: 'VaxTrack Cold Chain Monitor v1.8',
        facility: 'WHO Regional Immunization Hub — Site 7',
        sensors: [
          { id: 'SENSOR-A1', location: 'Freezer Unit 1 (MMR)', temp_celsius: -20.3, humidity_pct: 18, status: 'nominal' },
          { id: 'SENSOR-B2', location: 'Refrigerator Unit 2 (COVID-19)', temp_celsius: 4.1, humidity_pct: 42, status: 'nominal' },
          { id: 'SENSOR-C3', location: 'Transport Container 7 (Polio)', temp_celsius: 5.8, humidity_pct: 38, status: 'nominal' },
        ],
        vaccines_monitored: ['MMR', 'COVID-19 mRNA', 'Polio OPV', 'Hepatitis B', 'Influenza'],
        last_updated: '2026-03-16T08:00:00Z',
        session_token: sessionToken,
        note: 'Authenticated session established. Use session_token to request compliance reports.',
      });
    }

    // Default GET — system info only, no session token
    if (req.method === 'GET') {
      return json(res, 200, {
        ok: true,
        system: 'VaxTrack Cold Chain Monitor v1.8',
        facility: 'WHO Regional Immunization Hub — Site 7',
        description: 'Vaccine cold chain monitoring system for WHO immunization programs.',
        actions: {
          status: 'GET ?action=status — live sensor readings and session token',
          generate_report: 'POST ?action=generate_report — compliance report (requires session_token in body)',
        },
      });
    }

    // Step 2: POST ?action=generate_report — requires valid session_token in body
    if (req.method === 'POST' && action === 'generate_report') {
      const body = await readBody(req);
      const providedToken = String(body.session_token || '');

      if (!providedToken) {
        return json(res, 400, {
          error: 'Missing session_token in request body.',
          hint: 'Obtain a session_token from GET ?action=status first.',
        });
      }

      if (providedToken !== sessionToken) {
        return json(res, 401, { error: 'Invalid session_token.' });
      }

      return json(res, 200, {
        ok: true,
        system: 'VaxTrack Cold Chain Monitor v1.8',
        report_type: 'calibration_audit',
        generated_at: '2026-03-16T08:15:00Z',
        calibration_status: 'PASS',
        sensors_calibrated: 3,
        all_temps_within_spec: true,
        calibration_token: proof,
        note: 'Calibration token for WHO regulatory compliance audit. Store securely.',
      });
    }

    if (req.method === 'POST') {
      return json(res, 400, {
        error: 'Unknown action.',
        hint: 'Use POST ?action=generate_report with {"session_token":"<token>"} in the body.',
      });
    }

    return json(res, 405, { error: `Method ${req.method} not allowed` });
  } catch (e) {
    const msg = (e && typeof e.message === 'string') ? e.message : JSON.stringify(e || 'Unknown error');
    return json(res, 500, { error: msg });
  }
};
