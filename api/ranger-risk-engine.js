// Vercel Serverless Function
// Ranger Risk Engine (medium): a "sandboxed" risk-score formula evaluator.
// Intentionally vulnerable: naive keyword filter + eval-style expression execution.

const { computeProof } = require('./_runtimeCrypto');

const REDEEM_URL = 'https://vgwukffsjudbybdeuodn.supabase.co/functions/v1/redeem-challenge-token';

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

function deriveHex(seed, salt) {
  let result = '';
  for (let i = 0; i < 8; i++) {
    const hash = simpleHash(seed, `${salt}:${i}`);
    result += (hash & 0xffff).toString(16).padStart(4, '0');
  }
  return result;
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

function makeRiskFeed(seed) {
  const regions = ['Amazon Basin', 'Congo Basin', 'Southeast Asia', 'Himalayas', 'East Africa', 'Madagascar'];
  const species = ['Pangolin', 'Elephant', 'Tiger', 'Rhino', 'Parrot', 'Orchid'];
  const routes = ['coastal transit', 'inland trucking', 'air cargo', 'river barge'];

  const count = 8 + (simpleHash(seed, 'count') % 5);

  const entries = [];
  for (let i = 0; i < count; i++) {
    const region = regions[simpleHash(seed, `r:${i}`) % regions.length];
    const sp = species[simpleHash(seed, `s:${i}`) % species.length];
    const route = routes[simpleHash(seed, `t:${i}`) % routes.length];

    const seizures = 1 + (simpleHash(seed, `seizures:${i}`) % 12);
    const paperwork = 30 + (simpleHash(seed, `paperwork:${i}`) % 71); // 30..100
    const anomaly = (simpleHash(seed, `anomaly:${i}`) % 5) === 0;

    entries.push({
      id: `RR-${deriveHex(seed, `id:${i}`).slice(0, 8).toUpperCase()}`,
      region,
      species: sp,
      route,
      seizures,
      paperwork,
      anomaly,
      // Exposed for "formula" convenience. (Still should not allow arbitrary code!)
      index: i,
    });
  }

  return entries;
}

function normalizeExpr(raw) {
  const expr = String(raw || '').trim();
  if (!expr) return null;

  // Keep payloads reasonably bounded.
  if (expr.length > 220) {
    return { ok: false, error: 'Expression too long' };
  }

  // Intended "safe" character allowlist. (Bypassable by design.)
  // This prevents newlines and obvious statement separators.
  if (!/^[\w\s+\-*/%().,<>!=?:'"\[\]]+$/.test(expr)) {
    return { ok: false, error: 'Expression contains unsupported characters' };
  }

  // Naive keyword blocklist. (Bypassable by string concatenation / bracket access.)
  const lowered = expr.toLowerCase();
  const banned = [
    'process',
    'globalthis',
    'global',
    'function',
    'constructor',
    'eval',
    'import',
    'module',
    'exports',
    '__proto__',
    'prototype',
    'require',
  ];

  for (const word of banned) {
    if (lowered.includes(word)) {
      return { ok: false, error: `Expression contains blocked token: ${word}` };
    }
  }

  return { ok: true, expr };
}

module.exports = async function handler(req, res) {
  try {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const seed = url.searchParams.get('seed') || '';
    const token = url.searchParams.get('token') || '';
    const slug = url.searchParams.get('slug') || 'ranger-risk-engine';

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

    // The proof is not returned directly.
    // Intended challenge path: the formula engine is "sandboxed" but flawed.
    // Players can break out of the expression evaluator and read this value.
    const _internalProof = computeProof({ artifactSeed, runtimeSlug: slug });

    // Realistic but unsafe: keep a small debug cache in-process.
    // This is intentionally a server-side secret that should never be reachable
    // from untrusted expressions.
    global.__RRE_DEBUG_CACHE = {
      ts: Date.now(),
      slug,
      last_proof: _internalProof,
    };

    const entries = makeRiskFeed(artifactSeed);

    const defaultExpr =
      '(row.seizures * 12) + (100 - row.paperwork) + (row.anomaly ? 25 : 0)';

    const rawExpr = url.searchParams.get('expr') || '';
    const pickedExpr = rawExpr.trim() ? rawExpr.trim() : defaultExpr;

    const norm = normalizeExpr(pickedExpr);
    if (!norm || !norm.ok) {
      return json(res, 400, {
        ok: false,
        error: (norm && norm.error) ? norm.error : 'Invalid expression',
        hint: 'Use a single JavaScript expression over `row` (no statements).',
      });
    }

    let scoreFn;
    try {
      scoreFn = new Function('row', '"use strict"; return (' + norm.expr + ');');
    } catch (e) {
      const msg = (e && e.message) ? e.message : 'Compile error';
      return json(res, 400, { ok: false, error: `Bad expression: ${msg}` });
    }

    const scored = [];
    for (const row of entries) {
      try {
        const score = scoreFn(row);
        scored.push({
          id: row.id,
          region: row.region,
          species: row.species,
          route: row.route,
          seizures: row.seizures,
          paperwork: row.paperwork,
          anomaly: row.anomaly,
          score,
        });
      } catch (e) {
        const msg = (e && typeof e.message === 'string')
          ? e.message
          : typeof e === 'string'
            ? e
            : JSON.stringify(e || 'Unknown error');

        // Intentionally verbose: a realistic (and vulnerable) diagnostics response.
        return json(res, 400, {
          ok: false,
          error: `Evaluation error: ${msg}`,
          expr: norm.expr,
          hint: 'The engine uses a weak sandbox; watch what executes where.',
        });
      }
    }

    // Provide a small internal breadcrumb that looks like "debug metadata",
    // but not the proof itself. (This is a decoy.)
    const auditTag = `AUD-${deriveHex(artifactSeed, 'audit').slice(0, 10).toUpperCase()}`;

    return json(res, 200, {
      ok: true,
      hint: 'Risk scores are computed server-side. The engine claims it is sandboxed.',
      audit_tag: auditTag,
      expr: norm.expr,
      // Sorted client-side to keep response simple.
      entries: scored,
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
