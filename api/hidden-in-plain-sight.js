// Vercel Serverless Function
// Returns the per-team proof for Hidden in Plain Sight.

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
      const raw = errorData && (errorData.error ?? errorData.message);
      errorMessage =
        typeof raw === 'string'
          ? raw
          : raw
            ? JSON.stringify(raw)
            : errorMessage;
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
    const seed = url.searchParams.get('seed') || '';
    const token = url.searchParams.get('token') || '';

    let artifactSeed = '';
    if (seed) {
      artifactSeed = seed;
    } else {
      if (!token) return json(res, 400, { error: 'Missing token or seed' });
      const runtimeState = await redeemLaunchToken(token);
      artifactSeed = runtimeState.artifact_seed;
    }

    if (!/^[0-9a-f]{64}$/i.test(String(artifactSeed))) {
      return json(res, 400, { error: 'Invalid seed format' });
    }

    const proof = computeProof({ artifactSeed, runtimeSlug: 'hidden-in-plain-sight' });
    return json(res, 200, { ok: true, proof });
  } catch (e) {
    const msg = (e && typeof e.message === 'string')
      ? e.message
      : typeof e === 'string'
        ? e
        : JSON.stringify(e || 'Unknown error');
    return json(res, 500, { error: msg });
  }
};
