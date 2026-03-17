
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

function deriveAccessCode(seed) {
  // Short deterministic access code — not the proof, just a gate for Step 2
  let result = '';
  for (let i = 0; i < 4; i++) {
    const hash = simpleHash(seed, `ehr_access_code:${i}`);
    result += (hash & 0xffff).toString(16).padStart(4, '0');
  }
  return result; // 16 hex chars
}

const PATIENT_WHITELIST = new Set(['PT-1001', 'PT-1002', 'PT-1003', 'PT-1004', 'PT-1005']);

function getRecords(seed) {
  const accessCode = deriveAccessCode(seed);
  return {
    'PT-1001': { id: 'PT-1001', name: 'Jamie Torres', diagnosis: 'Hypertension', last_checkup: '2026-01-10', notes: 'Blood pressure stable on current medication regimen.' },
    'PT-1002': { id: 'PT-1002', name: 'Riley Kim', diagnosis: 'Type 2 Diabetes', last_checkup: '2026-02-03', notes: 'HbA1c improving with lifestyle modification program.' },
    'PT-1003': { id: 'PT-1003', name: 'Casey Park', diagnosis: 'Asthma', last_checkup: '2026-01-28', notes: 'Inhaler technique reviewed. Peak flow improved by 18%.' },
    'PT-1004': { id: 'PT-1004', name: 'Drew Morgan', diagnosis: 'Anxiety disorder', last_checkup: '2026-02-14', notes: 'CBT sessions ongoing. Medication adjusted at last visit.' },
    'PT-1005': { id: 'PT-1005', name: 'Avery Quinn', diagnosis: 'Migraine', last_checkup: '2026-03-01', notes: 'Trigger diary complete. Preventive therapy initiated.' },
    'SYS-ADMIN': {
      id: 'SYS-ADMIN',
      name: 'SYSTEM ADMINISTRATOR',
      diagnosis: 'N/A',
      last_checkup: 'N/A',
      notes: 'Administrative system record.',
      access_level: 'PRIVILEGED',
      admin_access_code: accessCode,
      note: 'Provide admin_access_code to the verify endpoint to obtain authorization.',
    },
  };
}

// Returns the LAST value of paramName from the raw query string
function getLastParam(rawQuery, paramName) {
  const parts = rawQuery.split('&');
  let last = null;
  for (const part of parts) {
    const eqIdx = part.indexOf('=');
    if (eqIdx === -1) continue;
    const key = decodeURIComponent(part.slice(0, eqIdx));
    const value = decodeURIComponent(part.slice(eqIdx + 1));
    if (key === paramName) last = value;
  }
  return last;
}

module.exports = async function handler(req, res) {
  try {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const seed = url.searchParams.get('seed') || '';

    if (!seed || !/^[0-9a-f]{64}$/i.test(String(seed))) {
      return json(res, 400, { error: 'Missing or invalid seed' });
    }

    const action = url.searchParams.get('action') || '';

    // POST ?action=verify — validates admin_access_code and returns proof
    if (action === 'verify') {
      if (req.method !== 'POST') return json(res, 405, { error: 'verify requires POST' });
      const body = await readBody(req);
      const providedCode = String(body.admin_access_code || '');
      if (!providedCode) {
        return json(res, 400, { error: 'Missing admin_access_code in request body.' });
      }
      if (providedCode !== deriveAccessCode(seed)) {
        return json(res, 403, { error: 'Invalid admin_access_code.' });
      }
      const proof = computeProof({ artifactSeed: seed, runtimeSlug: 'ehr-param-pollution' });
      return json(res, 200, {
        ok: true,
        system: 'HealthBridge EHR System v5.2',
        verified: true,
        access_level: 'PRIVILEGED',
        admin_token: proof,
        message: 'Admin access code verified. Authorization token issued.',
      });
    }

    // AUTH CHECK: url.searchParams.get() returns the FIRST occurrence
    const authPatientId = url.searchParams.get('patient_id') || '';

    if (!authPatientId) {
      return json(res, 400, {
        error: 'Missing patient_id parameter.',
        system: 'HealthBridge EHR System v5.2',
        hint: 'Provide ?patient_id=<id> to retrieve a patient record.',
        available_ids: Array.from(PATIENT_WHITELIST),
      });
    }

    if (!PATIENT_WHITELIST.has(authPatientId)) {
      return json(res, 403, {
        error: 'Access denied: patient_id not in authorized list.',
        authorized_ids: Array.from(PATIENT_WHITELIST),
      });
    }

    // DATA LOOKUP: parses raw query string and uses the LAST occurrence
    // This creates an HTTP parameter pollution vulnerability
    const rawQuery = url.search.slice(1);
    const lookupId = getLastParam(rawQuery, 'patient_id') || authPatientId;

    const records = getRecords(seed);
    const record = records[lookupId];

    if (!record) {
      return json(res, 404, { error: `Patient ${lookupId} not found.` });
    }

    return json(res, 200, {
      ok: true,
      system: 'HealthBridge EHR System v5.2',
      record,
    });
  } catch (e) {
    const msg = (e && typeof e.message === 'string') ? e.message : JSON.stringify(e || 'Unknown error');
    return json(res, 500, { error: msg });
  }
};
