// Vercel Serverless Function
// SDG 15: Illegal wildlife trade dashboard (mock internal API)
// Intentionally contains a logic flaw for the CTF challenge.

const REDEEM_URL = 'https://vgwukffsjudbybdeuodn.supabase.co/functions/v1/redeem-challenge-token';

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

function makeDataset(seed, slug) {
  const regions = ['Amazon Basin', 'Congo Basin', 'Southeast Asia', 'Himalayas', 'East Africa', 'Madagascar'];
  const species = ['Pangolin', 'Elephant', 'Tiger', 'Rhino', 'Parrot', 'Orchid'];

  const featuredRegion = regions[simpleHash(seed, 'featured_region') % regions.length];
  const featuredSpecies = species[simpleHash(seed, 'featured_species') % species.length];

  const featuredCaseId = `WPT-${deriveHex(seed, 'featured_case').slice(0, 8).toUpperCase()}`;
  const internalCaseId = `WPT-${deriveHex(seed, 'internal_case').slice(0, 8).toUpperCase()}`;

  const totalSeizures = 40 + (simpleHash(seed, 'total_seizures') % 260);
  const regionsAffected = 3 + (simpleHash(seed, 'regions_affected') % 4);
  const speciesProtected = 4 + (simpleHash(seed, 'species_protected') % 7);

  const cases = [
    {
      caseId: featuredCaseId,
      region: featuredRegion,
      species: featuredSpecies,
      product: 'Ivory (carved pieces)',
      summary: 'Declared as "craft materials"; inconsistent paperwork across ports.',
      // Hidden fields that should never be exposed by the aggregated endpoint.
      internal_notes: {
        investigator: `agent_${deriveHex(seed, 'agent').slice(0, 6)}`,
        escalation: 'Hold release pending inter-agency review.',
        evidence_bag: `BAG-${deriveHex(seed, 'bag').slice(0, 10).toUpperCase()}`,
        proof: computeProof({ artifactSeed: seed, runtimeSlug: slug }),
      },
    },
    {
      caseId: `WPT-${deriveHex(seed, 'case_b').slice(0, 8).toUpperCase()}`,
      region: regions[simpleHash(seed, 'r_b') % regions.length],
      species: species[simpleHash(seed, 's_b') % species.length],
      product: 'Pangolin scales (compressed bales)',
      summary: 'Repeated routing through shell forwarding agents.',
    },
    {
      caseId: `WPT-${deriveHex(seed, 'case_c').slice(0, 8).toUpperCase()}`,
      region: regions[simpleHash(seed, 'r_c') % regions.length],
      species: species[simpleHash(seed, 's_c') % species.length],
      product: 'Exotic bird feathers (bundled)',
      summary: 'Counterfeit export permits; batch identifiers reused.',
    },
    {
      caseId: internalCaseId,
      region: 'Port Authority (internal)',
      species: 'Mixed (internal)',
      product: 'Redacted',
      summary: 'Internal suppression request logged; case details restricted.',
      // This is the hidden internal record.
      internal_notes: {
        investigator: `agent_${deriveHex(seed, 'agent').slice(0, 6)}`,
        escalation: 'Hold release pending inter-agency review.',
        evidence_bag: `BAG-${deriveHex(seed, 'bag').slice(0, 10).toUpperCase()}`,
        proof: null,
      },
    },
  ];

  return {
    totals: {
      totalSeizures,
      regionsAffected,
      speciesProtected,
    },
    featuredCaseId,
    internalCaseId,
    cases,
  };
}

function safeParseFilter(raw) {
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object') return null;
    return parsed;
  } catch {
    return null;
  }
}

module.exports = async function handler(req, res) {
  try {
    const token = typeof req.query.token === 'string' ? req.query.token : '';
    const slug = typeof req.query.slug === 'string' ? req.query.slug : 'poacher-supply-chain';

    if (!token) {
      return json(res, 400, { error: 'Missing token' });
    }

    // Redeem the launch token server-side to get the per-team artifact_seed.
    // This reuses the same launch-token system as the runtime.
    const runtimeState = await redeemLaunchToken(token);
    const seed = runtimeState.artifact_seed;

    const dataset = makeDataset(seed, slug);

    // Intended policy:
    // - Only aggregated statistics should be exposed here.
    // - Case details must be accessed via /api/cases/:id and require elevated auth.
    //
    // Implemented (vulnerable) policy:
    // - We block direct ?caseId=...
    // - BUT we accidentally allow a case lookup when embedded in the JSON filter.
    const directCaseId = typeof req.query.caseId === 'string' ? req.query.caseId.trim() : '';
    if (directCaseId) {
      return json(res, 403, { error: 'Direct case access is restricted. Use aggregated endpoints only.' });
    }

    const filter = safeParseFilter(typeof req.query.filter === 'string' ? req.query.filter : '');

    const regionParam = (typeof req.query.region === 'string' ? req.query.region : '').trim();
    const speciesParam = (typeof req.query.species === 'string' ? req.query.species : '').trim();
    const region = regionParam || (filter && typeof filter.region === 'string' ? filter.region.trim() : '');
    const species = speciesParam || (filter && typeof filter.species === 'string' ? filter.species.trim() : '');

    const filtered = dataset.cases.filter((c) => {
      if (region && c.region !== region) return false;
      if (species && c.species !== species) return false;
      return true;
    });

    // Aggregated, public response.
    const response = {
      ok: true,
      totals: dataset.totals,
      regions: Array.from(new Set(dataset.cases.map((c) => c.region))).filter((r) => !r.includes('(internal)')),
      species: Array.from(new Set(dataset.cases.map((c) => c.species))).filter((s) => !s.includes('(internal)')),
      featured_case: filtered[0]
        ? {
            caseId: filtered[0].caseId,
            region: filtered[0].region,
            species: filtered[0].species,
            product: filtered[0].product,
            summary: filtered[0].summary,
          }
        : null,
    };

    // VULNERABILITY (BOLA via filter embedding):
    // If a client embeds caseId inside filter JSON, we return a case record.
    // This bypasses the intended restriction.
    const embeddedCaseId = filter && typeof filter.caseId === 'string' ? filter.caseId.trim() : '';
    if (embeddedCaseId) {
      const match = dataset.cases.find((c) => c.caseId === embeddedCaseId);
      if (match) {
        response.case_detail = match; // includes internal_notes for the internal record
      }
    }

    return json(res, 200, response);
  } catch (e) {
    const msg = (e && e.message) ? e.message : 'Unknown error';
    return json(res, 500, { error: msg });
  }
};
