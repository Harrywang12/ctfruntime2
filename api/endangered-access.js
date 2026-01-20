// Vercel Serverless Function
// Returns "restricted telemetry" for Endangered Access.
// Intentionally: server does NOT enforce access; the client gate is fake.

const { computeProof } = require('./_runtimeCrypto');

const REDEEM_URL = 'https://vgwukffsjudbybdeuodn.supabase.co/functions/v1/redeem-challenge-token';

function json(res, status, body) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(body));
}

async function redeemLaunchToken(token) {
  const response = await fetch(REDEEM_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`,
    },
    body: JSON.stringify({ token }),
  });

  if (!response.ok) {
    let errorMessage = `HTTP ${response.status}`;
    try {
      const errorData = await response.json();
      errorMessage = errorData.error || errorData.message || errorMessage;
    } catch {
      errorMessage = response.statusText || errorMessage;
    }
    throw new Error(errorMessage);
  }

  const data = await response.json();
  if (!data || !data.artifact_seed) {
    throw new Error('Invalid redeem response');
  }
  return data;
}

module.exports = async function handler(req, res) {
  try {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const token = url.searchParams.get('token') || '';
    const slug = url.searchParams.get('slug') || 'endangered-access';
    if (!token) return json(res, 400, { error: 'Missing token' });

    const runtimeState = await redeemLaunchToken(token);
    const artifactSeed = runtimeState.artifact_seed;

    const proof = computeProof({ artifactSeed, runtimeSlug: slug });

    // Mock telemetry. The important part is the proof.
    return json(res, 200, {
      ok: true,
      restricted: true,
      telemetry: {
        hotspot: 'Ranger Station 4',
        region: 'Protected Corridor',
        last_ping_minutes: 7,
        anomalies: ['tampered GPS collar', 'unregistered transport manifest'],
        site_hash: proof,
      },
    });
  } catch (e) {
    const msg = (e && typeof e.message === 'string')
      ? e.message
      : typeof e === 'string'
        ? e
        : JSON.stringify(e || 'Unknown error');
    return json(res, 500, { error: msg });
  }
};
