
const { computeProof } = require('./_runtimeCrypto');

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

function deriveHex(seed, salt, len) {
  let result = '';
  for (let i = 0; i < 8; i++) {
    const hash = simpleHash(seed, `${salt}:${i}`);
    result += (hash & 0xffff).toString(16).padStart(4, '0');
  }
  return result.slice(0, len || 32);
}

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

function makeDatabase(seed) {
  const proof = computeProof({ artifactSeed: seed, runtimeSlug: 'health-data-nosql' });
  const hiddenSuffix = deriveHex(seed, 'trial_hidden', 4);
  const hiddenField = `trial_code_${hiddenSuffix}`;

  const records = [
    { id: 'TRL-001', participant: 'Participant A', trial: 'SDG3-HYPERTENSION-2025', arm: 'control', enrolled: '2025-06-01', outcome: 'bp_normalised', status: 'completed' },
    { id: 'TRL-002', participant: 'Participant B', trial: 'SDG3-HYPERTENSION-2025', arm: 'treatment', enrolled: '2025-06-01', outcome: 'bp_improved', status: 'completed' },
    { id: 'TRL-003', participant: 'Participant C', trial: 'SDG3-DIABETES-PREV', arm: 'treatment', enrolled: '2025-07-15', outcome: 'pending', status: 'active' },
    { id: 'TRL-004', participant: 'Participant D', trial: 'SDG3-MENTAL-HEALTH', arm: 'control', enrolled: '2025-08-20', outcome: 'pending', status: 'active' },
    { id: 'TRL-CLASSIFIED', participant: 'REDACTED', trial: 'SDG3-CLASSIFIED-PROTOCOL', arm: 'classified', enrolled: 'REDACTED', outcome: 'classified', status: 'classified', [hiddenField]: proof },
  ];

  return { records, hiddenField };
}

function matchesFilter(record, filter) {
  for (const [key, condition] of Object.entries(filter)) {
    const value = record[key];
    if (condition && typeof condition === 'object') {
      if ('$exists' in condition) {
        const exists = key in record;
        if (condition.$exists && !exists) return false;
        if (!condition.$exists && exists) return false;
        continue;
      }
      if ('$regex' in condition) {
        try {
          const re = new RegExp(condition.$regex, condition.$options || '');
          if (typeof value !== 'string' || !re.test(value)) return false;
        } catch { return false; }
        continue;
      }
      if ('$eq' in condition) { if (value !== condition.$eq) return false; continue; }
      if ('$gt' in condition && !(value > condition.$gt)) return false;
      if ('$lt' in condition && !(value < condition.$lt)) return false;
      if ('$gte' in condition && !(value >= condition.$gte)) return false;
      if ('$lte' in condition && !(value <= condition.$lte)) return false;
    } else {
      if (value !== condition) return false;
    }
  }
  return true;
}

module.exports = async function handler(req, res) {
  try {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const seed = url.searchParams.get('seed') || '';
    const action = url.searchParams.get('action') || 'schema';

    if (!seed || !/^[0-9a-f]{64}$/i.test(String(seed))) {
      return json(res, 400, { error: 'Missing or invalid seed' });
    }

    const { records, hiddenField } = makeDatabase(seed);

    if (action === 'schema') {
      return json(res, 200, {
        ok: true,
        system: 'ClinicalDB Trial Data API v3.0',
        schema: {
          fields: ['id', 'participant', 'trial', 'arm', 'enrolled', 'outcome', 'status'],
          note: 'Documented public fields. Classified records may contain additional fields.',
        },
        query_format: {
          method: 'POST',
          endpoint: '?seed=<seed>&action=query',
          body: '{ "filter": { "<field>": "<value_or_operator>" } }',
          operators: ['$eq', '$regex', '$exists', '$gt', '$lt', '$gte', '$lte'],
          example: '{ "filter": { "status": "completed" } }',
        },
        hints: [
          'Classified trial records may contain fields not listed in this schema.',
          'Use ?action=fields to enumerate all field names including undocumented ones.',
          'The $exists operator tests whether a field is present on a record.',
          'Hidden field names follow the pattern: trial_code_<4 hex chars>.',
        ],
      });
    }

    if (action === 'fields') {
      const allFields = new Set();
      for (const r of records) for (const k of Object.keys(r)) allFields.add(k);
      return json(res, 200, {
        ok: true,
        all_fields: Array.from(allFields).sort(),
        note: 'All field names across all records, including undocumented ones.',
      });
    }

    if (action === 'query') {
      if (req.method !== 'POST') return json(res, 405, { error: 'Query action requires POST' });
      const body = await readBody(req);
      const filter = body.filter;
      if (!filter || typeof filter !== 'object') return json(res, 400, { error: 'Missing or invalid filter object' });

      const matched = records.filter((r) => matchesFilter(r, filter));
      const sanitized = matched.map((r) => {
        const copy = { ...r };
        if (hiddenField in copy) {
          delete copy[hiddenField];
          copy._has_classified_field = true;
        }
        return copy;
      });

      return json(res, 200, {
        ok: true,
        count: sanitized.length,
        results: sanitized,
      });
    }

    if (action === 'extract') {
      if (req.method !== 'POST') return json(res, 405, { error: 'Extract action requires POST' });
      const body = await readBody(req);
      const { regex, record_id } = body;
      if (!regex || typeof regex !== 'string') return json(res, 400, { error: 'Missing regex string in body' });
      if (!record_id || typeof record_id !== 'string') return json(res, 400, { error: 'Missing record_id in body' });

      const record = records.find((r) => r.id === record_id);
      if (!record) return json(res, 404, { error: 'Record not found' });

      const hiddenValue = record[hiddenField];
      if (!hiddenValue) {
        return json(res, 200, { ok: true, match: false, note: 'This record has no classified field.' });
      }

      try {
        const re = new RegExp(regex);
        const match = re.test(hiddenValue);
        return json(res, 200, { ok: true, match });
      } catch (e) {
        return json(res, 400, { error: `Invalid regex: ${e.message}` });
      }
    }

    return json(res, 400, { error: 'Unknown action. Use: schema, fields, query, extract' });
  } catch (e) {
    const msg = (e && typeof e.message === 'string') ? e.message : JSON.stringify(e || 'Unknown error');
    return json(res, 500, { error: msg });
  }
};
