// Vercel Serverless Function
// Returns the per-team proof for Save the Species.

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
    const token = typeof req.query.token === 'string' ? req.query.token : '';
    if (!token) return json(res, 400, { error: 'Missing token' });

    const runtimeState = await redeemLaunchToken(token);
    const artifactSeed = runtimeState.artifact_seed;

    const proof = computeProof({ artifactSeed, runtimeSlug: 'save-the-species' });
    return json(res, 200, { ok: true, proof });
  } catch (e) {
    const msg = (e && e.message) ? e.message : 'Unknown error';
    return json(res, 500, { error: msg });
  }
};
