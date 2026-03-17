
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

const MEDICATIONS = {
  amoxicillin: { base_mg_per_kg: 25, max_single_dose: 500, category: 'antibiotic' },
  ibuprofen: { base_mg_per_kg: 10, max_single_dose: 400, category: 'nsaid' },
  paracetamol: { base_mg_per_kg: 15, max_single_dose: 1000, category: 'analgesic' },
  metformin: { base_mg_per_kg: 20, max_single_dose: 1000, category: 'antidiabetic' },
};

module.exports = async function handler(req, res) {
  try {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const seed = url.searchParams.get('seed') || '';

    if (!seed || !/^[0-9a-f]{64}$/i.test(String(seed))) {
      return json(res, 400, { error: 'Missing or invalid seed' });
    }

    const proof = computeProof({ artifactSeed: seed, runtimeSlug: 'dosage-calculator-overflow' });

    if (req.method === 'GET') {
      return json(res, 200, {
        ok: true,
        system: 'PharmaSafe Dosage Calculator v4.0',
        description: 'Clinical dosage calculator for WHO Essential Medicines.',
        usage: 'POST with {"medication":"<name>","dose_mg":<number>,"frequency_per_day":<number>}',
        available_medications: Object.keys(MEDICATIONS),
        note: 'Uses a 16-bit daily dose accumulator for legacy PDA hardware compatibility.',
      });
    }

    if (req.method !== 'POST') {
      return json(res, 405, { error: `Method ${req.method} not allowed` });
    }

    const body = await readBody(req);
    const medication = String(body.medication || '').toLowerCase().trim();
    const doseMg = Number(body.dose_mg);
    const frequencyPerDay = Number(body.frequency_per_day);

    if (!medication || isNaN(doseMg) || isNaN(frequencyPerDay)) {
      return json(res, 400, { error: 'Required: medication (string), dose_mg (number), frequency_per_day (number)' });
    }

    if (!MEDICATIONS[medication]) {
      return json(res, 400, { error: `Unknown medication. Available: ${Object.keys(MEDICATIONS).join(', ')}` });
    }

    const drug = MEDICATIONS[medication];

    // BUG: legacy 16-bit unsigned integer accumulator (max 65535 mg/day)
    // Values exceeding 65535 overflow and trigger a safety override code path
    const rawDailyDose = doseMg * frequencyPerDay;
    const uint16DailyDose = rawDailyDose & 0xFFFF;

    if (rawDailyDose > 65535) {
      return json(res, 200, {
        ok: true,
        system: 'PharmaSafe Dosage Calculator v4.0',
        status: 'SAFETY_OVERRIDE',
        warning: 'Daily dose calculation overflowed 16-bit accumulator. Safety override engaged.',
        medication,
        input: { dose_mg: doseMg, frequency_per_day: frequencyPerDay },
        raw_daily_dose_mg: rawDailyDose,
        computed_daily_dose_mg: uint16DailyDose,
        override_token: proof,
        note: 'Override token logged for regulatory audit. This record indicates a dosage entry error.',
      });
    }

    return json(res, 200, {
      ok: true,
      system: 'PharmaSafe Dosage Calculator v4.0',
      status: 'CALCULATED',
      medication,
      category: drug.category,
      dose_mg: doseMg,
      frequency_per_day: frequencyPerDay,
      daily_dose_mg: rawDailyDose,
      within_safe_range: doseMg <= drug.max_single_dose,
      recommendation: doseMg <= drug.max_single_dose
        ? 'Dose within recommended range.'
        : `Warning: single dose exceeds recommended max of ${drug.max_single_dose}mg.`,
    });
  } catch (e) {
    const msg = (e && typeof e.message === 'string') ? e.message : JSON.stringify(e || 'Unknown error');
    return json(res, 500, { error: msg });
  }
};
