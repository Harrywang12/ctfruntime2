
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

    const proof = computeProof({ artifactSeed: seed, runtimeSlug: 'factory-maintenance' });

    // GET: return maintenance status without proof
    if (req.method === 'GET') {
      return json(res, 200, {
        ok: true,
        status: 'maintenance',
        system: 'SDG9 Industrial Control Panel v2.4.1',
        message: 'Factory is undergoing scheduled maintenance. Systems nominal.',
        allowed_methods: ['GET', 'POST'],
        diagnostics: {
          uptime_hours: 1847,
          last_inspection: '2026-01-15T08:00:00Z',
          next_inspection: '2026-03-01T08:00:00Z',
          firmware: 'ICPv2.4.1-stable',
        },
        hint: 'Maintenance reports can be submitted via POST. The system responds differently to different HTTP methods.',
      });
    }

    // POST: return the proof (the "maintenance override" response)
    if (req.method === 'POST') {
      return json(res, 200, {
        ok: true,
        status: 'override_accepted',
        system: 'SDG9 Industrial Control Panel v2.4.1',
        message: 'Maintenance override acknowledged. Diagnostic dump follows.',
        diagnostic_dump: {
          core_temp_c: 72.4,
          pressure_bar: 3.1,
          maintenance_token: proof,
          override_level: 'TECHNICIAN',
        },
      });
    }

    return json(res, 405, { error: `Method ${req.method} not allowed` });
  } catch (e) {
    const msg = (e && typeof e.message === 'string') ? e.message : JSON.stringify(e || 'Unknown error');
    return json(res, 500, { error: msg });
  }
};
