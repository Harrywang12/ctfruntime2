// Vercel Serverless Function
// Simulated permit verification service for Illegal Logging Network.
// Intentionally flawed verification logic.

const crypto = require('crypto');
const { computeProof } = require('./_runtimeCrypto');

const REDEEM_URL = 'https://vgwukffsjudbybdeuodn.supabase.co/functions/v1/redeem-challenge-token';

function json(res, status, body) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(body));
}

function sha256Hex(s) {
  return crypto.createHash('sha256').update(String(s), 'utf8').digest('hex');
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

// Token format: VER-<permitId>-<sig>
// Intended: sig == sha256(permitId).slice(0, 8)
// Bug: only checks the first 2 hex chars (prefix match), letting attackers forge.
function verifyTokenFlawed(token) {
  if (!token.startsWith('VER-')) return { ok: false, error: 'Token must start with VER-' };

  const parts = token.split('-');
  if (parts.length < 3) return { ok: false, error: 'Malformed token' };

  const permitId = parts.slice(1, -1).join('-');
  const sig = parts[parts.length - 1] || '';

  if (!permitId || permitId.length < 4) return { ok: false, error: 'Permit ID too short' };
  if (!/^[a-z0-9-]+$/i.test(permitId)) return { ok: false, error: 'Invalid permit ID characters' };
  if (!/^[0-9a-f]{2,}$/i.test(sig)) return { ok: false, error: 'Invalid signature encoding' };

  const expected = sha256Hex(permitId).slice(0, 8);

  // Flaw: only checks two chars.
  const ok = sig.toLowerCase().startsWith(expected.slice(0, 2));
  return { ok, permitId, expectedPrefix: expected.slice(0, 2) };
}

module.exports = async function handler(req, res) {
  try {
    const token = typeof req.query.token === 'string' ? req.query.token : '';
    const slug = typeof req.query.slug === 'string' ? req.query.slug : 'illegal-logging-network';
    const verificationToken = typeof req.query.verificationToken === 'string' ? req.query.verificationToken.trim() : '';

    if (!token) return json(res, 400, { error: 'Missing token' });
    if (!verificationToken) return json(res, 400, { error: 'Missing verificationToken' });

    const verdict = verifyTokenFlawed(verificationToken);
    if (!verdict.ok) {
      return json(res, 403, { ok: false, error: verdict.error || 'Verification failed' });
    }

    const runtimeState = await redeemLaunchToken(token);
    const artifactSeed = runtimeState.artifact_seed;

    const proof = computeProof({ artifactSeed, runtimeSlug: slug });

    return json(res, 200, {
      ok: true,
      permitId: verdict.permitId,
      // Do not leak full expected signature; this is just a realistic audit crumb.
      audit: { sig_prefix_matched: verdict.expectedPrefix },
      proof,
    });
  } catch (e) {
    const msg = (e && e.message) ? e.message : 'Unknown error';
    return json(res, 500, { error: msg });
  }
};
