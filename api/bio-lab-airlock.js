

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
            try {
                resolve(data ? JSON.parse(data) : {});
            } catch {
                resolve({});
            }
        });
        req.on('error', reject);
    });
}

function makeDatabase(seed) {
    const proof = computeProof({ artifactSeed: seed, runtimeSlug: 'bio-lab-airlock' });

    // Randomized hidden field name
    const hiddenFieldSuffix = deriveHex(seed, 'hidden_field', 4);
    const hiddenFieldName = `specimen_${hiddenFieldSuffix}`;

    const records = [
        {
            id: 'BIO-001',
            name: 'E. coli K-12',
            biosafety_level: 1,
            containment: 'standard',
            status: 'stored',
        },
        {
            id: 'BIO-002',
            name: 'Mycobacterium tuberculosis',
            biosafety_level: 3,
            containment: 'enhanced',
            status: 'active_research',
        },
        {
            id: 'BIO-003',
            name: 'Bacillus anthracis (attenuated)',
            biosafety_level: 2,
            containment: 'standard',
            status: 'stored',
        },
        {
            id: 'BIO-004',
            name: 'SARS-CoV-2 (inactivated)',
            biosafety_level: 3,
            containment: 'bsl3_cabinet',
            status: 'active_research',
        },
        {
            id: 'BIO-005',
            name: 'Classified Specimen',
            biosafety_level: 4,
            containment: 'maximum',
            status: 'quarantined',
            [hiddenFieldName]: proof,
        },
    ];

    return { records, hiddenFieldName };
}

function matchesFilter(record, filter) {
    for (const [key, condition] of Object.entries(filter)) {
        const value = record[key];

        if (condition && typeof condition === 'object') {
            // $exists operator
            if ('$exists' in condition) {
                const exists = key in record;
                if (condition.$exists && !exists) return false;
                if (!condition.$exists && exists) return false;
                continue;
            }

            // $regex operator
            if ('$regex' in condition) {
                try {
                    const re = new RegExp(condition.$regex, condition.$options || '');
                    if (typeof value !== 'string' || !re.test(value)) return false;
                } catch {
                    return false;
                }
                continue;
            }

            // $eq operator
            if ('$eq' in condition) {
                if (value !== condition.$eq) return false;
                continue;
            }

            // $gt, $lt, $gte, $lte
            if ('$gt' in condition && !(value > condition.$gt)) return false;
            if ('$lt' in condition && !(value < condition.$lt)) return false;
            if ('$gte' in condition && !(value >= condition.$gte)) return false;
            if ('$lte' in condition && !(value <= condition.$lte)) return false;
        } else {
            // Direct equality
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

        const { records, hiddenFieldName } = makeDatabase(seed);

        if (action === 'schema') {
            // Intentionally omits the hidden field from the schema
            return json(res, 200, {
                ok: true,
                system: 'BioLab Airlock Specimen Database v4.2',
                schema: {
                    fields: ['id', 'name', 'biosafety_level', 'containment', 'status'],
                    note: 'All documented fields listed above.',
                },
                query_format: {
                    method: 'POST',
                    endpoint: '?seed=<seed>&action=query',
                    body: '{ "filter": { "<field>": "<value>" } }',
                    operators: ['$eq', '$regex', '$exists', '$gt', '$lt', '$gte', '$lte'],
                    example: '{ "filter": { "biosafety_level": { "$gte": 3 } } }',
                },
                hints: [
                    'The schema lists documented fields, but are there any undocumented ones?',
                    'Some records may have fields not shown in the schema.',
                    'The $exists operator can test whether a field is present on a record.',
                    'Field names follow the pattern: specimen_<4 hex chars>.',
                ],
            });
        }

        if (action === 'fields') {
            // Lists all unique field names across records (intentionally includes hidden field).
            // But only returns field names, not values.
            const allFields = new Set();
            for (const record of records) {
                for (const key of Object.keys(record)) {
                    allFields.add(key);
                }
            }

            return json(res, 200, {
                ok: true,
                all_fields: Array.from(allFields).sort(),
                note: 'This lists all fields present across all records, including undocumented ones.',
            });
        }

        if (action === 'query') {
            if (req.method !== 'POST') {
                return json(res, 405, { error: 'Query action requires POST' });
            }

            const body = await readBody(req);
            const filter = body.filter;

            if (!filter || typeof filter !== 'object') {
                return json(res, 400, { error: 'Missing or invalid filter object in body' });
            }

            // Security: strip hidden field values from results
            const matched = records.filter((r) => matchesFilter(r, filter));
            const sanitized = matched.map((r) => {
                const copy = { ...r };
                // Remove hidden field from output (blind query: you can check existence but not read)
                if (hiddenFieldName in copy) {
                    delete copy[hiddenFieldName];
                    copy._has_hidden_field = true;
                }
                return copy;
            });

            return json(res, 200, {
                ok: true,
                count: sanitized.length,
                results: sanitized,
                hint: sanitized.some((r) => r._has_hidden_field)
                    ? 'A matched record has a hidden field. Its value is not returned directly. Try $regex to test against it.'
                    : undefined,
            });
        }

        if (action === 'extract') {
            // Blind extraction endpoint: tests a regex against the hidden field value
            // Returns only true/false, not the actual value.
            if (req.method !== 'POST') {
                return json(res, 405, { error: 'Extract action requires POST' });
            }

            const body = await readBody(req);
            const regex = body.regex;
            const recordId = body.record_id;

            if (!regex || typeof regex !== 'string') {
                return json(res, 400, { error: 'Missing regex string in body' });
            }

            if (!recordId || typeof recordId !== 'string') {
                return json(res, 400, { error: 'Missing record_id in body' });
            }

            // Find the record
            const record = records.find((r) => r.id === recordId);
            if (!record) {
                return json(res, 404, { error: 'Record not found' });
            }

            // Test regex against the hidden field value
            const hiddenValue = record[hiddenFieldName];
            if (!hiddenValue) {
                return json(res, 200, {
                    ok: true,
                    match: false,
                    note: 'This record does not have the hidden field.',
                });
            }

            try {
                const re = new RegExp(regex);
                const match = re.test(hiddenValue);
                return json(res, 200, {
                    ok: true,
                    match,
                    // Intentionally do NOT return the value
                    hint: match
                        ? 'Regex matched the hidden field value. Narrow your regex to extract character by character.'
                        : 'No match. Try a different pattern.',
                });
            } catch (e) {
                return json(res, 400, { error: `Invalid regex: ${e.message}` });
            }
        }

        return json(res, 400, { error: 'Unknown action. Use schema, fields, query, or extract.' });
    } catch (e) {
        const msg = (e && typeof e.message === 'string') ? e.message : JSON.stringify(e || 'Unknown error');
        return json(res, 500, { error: msg });
    }
};
