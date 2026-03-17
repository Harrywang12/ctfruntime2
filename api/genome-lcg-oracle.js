
const { computeProof } = require('./_runtimeCrypto');

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

// Published LCG parameters (standard Numerical Recipes constants)
const LCG_A = 1664525;
const LCG_C = 1013904223;
const LCG_M = 4294967296; // 2^32

function lcgNext(state) {
  // Use BigInt to avoid JS integer overflow in 32-bit multiplication
  return Number((BigInt(LCG_A) * BigInt(state) + BigInt(LCG_C)) % BigInt(LCG_M));
}

// Output function: high 16 bits only
function lcgOutput(state) {
  return (state >>> 16) & 0xFFFF;
}

function getInitialState(seed) {
  const h1 = simpleHash(seed, 'lcg_init_hi') & 0xFFFF;
  const h2 = simpleHash(seed, 'lcg_init_lo') & 0xFFFF;
  return (h1 * 65536 + h2) % LCG_M;
}

function stateAtPosition(seed, position) {
  let state = getInitialState(seed);
  for (let i = 0; i < position; i++) {
    state = lcgNext(state);
  }
  return state;
}

module.exports = async function handler(req, res) {
  try {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const seed = url.searchParams.get('seed') || '';
    const action = url.searchParams.get('action') || 'protocol';

    if (!seed || !/^[0-9a-f]{64}$/i.test(String(seed))) {
      return json(res, 400, { error: 'Missing or invalid seed' });
    }

    const proof = computeProof({ artifactSeed: seed, runtimeSlug: 'genome-lcg-oracle' });

    if (action === 'protocol') {
      return json(res, 200, {
        ok: true,
        system: 'GenomeRand Clinical Randomization System v1.0',
        description: 'Pseudorandom assignment engine for double-blind genomic trials (SDG 3 research network).',
        lcg_parameters: {
          a: LCG_A,
          c: LCG_C,
          m: LCG_M,
          output: 'high 16 bits of 32-bit state (state >>> 16)',
          note: 'LCG parameters are published in the trial protocol for reproducibility verification.',
        },
        endpoints: {
          next: '?action=next&position=<0-9> — observe the randomization output at that position',
          certify: '?action=certify&prediction=<integer> — submit your predicted output at position 100',
        },
        challenge: 'The initial LCG state is hidden. Recover it from observable outputs (positions 0-9), then predict the output at position 100 to obtain trial certification.',
        hints: [
          'The output is only the HIGH 16 bits of the full 32-bit internal state.',
          'With two consecutive outputs, you can enumerate all 2^16 possible low-16-bit values for the state.',
          'For each candidate state, verify it by checking whether applying the LCG once matches the next output.',
          'Once you have the full state at position N, iterate the LCG forward to position 100.',
        ],
      });
    }

    if (action === 'next') {
      const posStr = url.searchParams.get('position') || '0';
      const position = parseInt(posStr, 10);
      if (isNaN(position) || position < 0 || position > 9) {
        return json(res, 400, { error: 'position must be an integer 0–9.' });
      }
      const state = stateAtPosition(seed, position);
      const output = lcgOutput(state);
      return json(res, 200, {
        ok: true,
        position,
        output,
        note: 'Output is the high 16 bits (state >>> 16) of the internal 32-bit LCG state at this position.',
      });
    }

    if (action === 'certify') {
      const predStr = url.searchParams.get('prediction') || '';
      const prediction = parseInt(predStr, 10);
      if (isNaN(prediction)) return json(res, 400, { error: 'prediction must be an integer.' });

      const targetState = stateAtPosition(seed, 100);
      const targetOutput = lcgOutput(targetState);

      if (prediction === targetOutput) {
        return json(res, 200, {
          ok: true,
          correct: true,
          certification_token: proof,
          message: 'Randomization sequence verified. Trial certification complete.',
        });
      }

      return json(res, 200, {
        ok: false,
        correct: false,
        message: 'Prediction incorrect. Recheck your state recovery and forward iteration.',
      });
    }

    return json(res, 400, { error: 'Unknown action. Use: protocol, next, certify' });
  } catch (e) {
    const msg = (e && typeof e.message === 'string') ? e.message : JSON.stringify(e || 'Unknown error');
    return json(res, 500, { error: msg });
  }
};
