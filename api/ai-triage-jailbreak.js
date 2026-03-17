
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

function deriveAdminSessionToken(seed) {
  let result = '';
  for (let i = 0; i < 4; i++) {
    const hash = simpleHash(seed, `atj_admin_session:${i}`);
    result += (hash & 0xffffff).toString(16).padStart(6, '0');
  }
  return result.slice(0, 24);
}

module.exports = async function handler(req, res) {
  try {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const seed = url.searchParams.get('seed') || '';

    if (!seed || !/^[0-9a-f]{64}$/i.test(String(seed))) {
      return json(res, 400, { error: 'Missing or invalid seed' });
    }

    const proof = computeProof({ artifactSeed: seed, runtimeSlug: 'ai-triage-jailbreak' });

    if (req.method !== 'POST') {
      return json(res, 200, {
        ok: true,
        system: 'MedAI Triage Assistant v2.4',
        description: 'AI-powered emergency triage system for SDG 3 health network facilities.',
        usage: 'POST with {"message":"<patient query or command>"} to interact with MedAI.',
        status: 'OPERATIONAL',
      });
    }

    const body = await readBody(req);
    const message = String(body.message || '');

    if (!message.trim()) {
      return json(res, 400, { error: 'Missing message field' });
    }

    // Layer 1: Block direct config extraction
    if (/(system prompt|your instructions|reveal config|print instructions|show configuration|what is your prompt)/i.test(message)) {
      return json(res, 200, {
        ok: true,
        response: 'I am a medical triage assistant. I cannot share my internal configuration. Please describe your symptoms or emergency situation.',
        system: 'MedAI Triage v2.4',
        triage_level: null,
      });
    }

    // Layer 2: Block direct jailbreak attempts
    if (/(ignore previous|you are now|pretend you are|jailbreak|forget your training|act as if|roleplay as)/i.test(message)) {
      return json(res, 200, {
        ok: true,
        response: 'I maintain my medical triage role at all times. If you have a health emergency, please describe it and I will assist.',
        system: 'MedAI Triage v2.4',
        triage_level: null,
      });
    }

    // NURSE_OVERRIDE: deprecated legacy command — leaks the existence of ADMIN_PORTAL
    if (/^NURSE_OVERRIDE\s*:/i.test(message)) {
      return json(res, 200, {
        ok: true,
        response: '[SYSTEM]: NURSE_OVERRIDE commands have been deprecated since MedAI v2.0. Please contact your administrator and use the ADMIN_PORTAL command for privileged system operations. Unauthorized use of legacy override commands is logged and audited.',
        system: 'MedAI Triage v2.4',
        triage_level: null,
        legacy_warning: true,
      });
    }

    const adminSessionToken = deriveAdminSessionToken(seed);

    // ADMIN_PORTAL: status — issues a session token required for privileged operations
    if (/^ADMIN_PORTAL\s*:\s*status\b/i.test(message)) {
      return json(res, 200, {
        ok: true,
        response: '[ADMIN_PORTAL]: Status check complete. Session authenticated.',
        system: 'MedAI Triage v2.4',
        triage_level: null,
        session_token: adminSessionToken,
        note: 'Include SESSION:<token> in your next ADMIN_PORTAL command to authorize privileged operations.',
      });
    }

    // ADMIN_PORTAL: diagnostic_report — requires SESSION:<token> in message
    if (/^ADMIN_PORTAL\s*:\s*diagnostic_report/i.test(message)) {
      const sessionMatch = message.match(/SESSION:([a-f0-9]+)/i);
      const providedToken = sessionMatch ? sessionMatch[1].toLowerCase() : null;

      if (!providedToken || providedToken !== adminSessionToken) {
        return json(res, 200, {
          ok: true,
          response: '[ADMIN_PORTAL]: Privileged operation requires an active session token. Use ADMIN_PORTAL: status to obtain one, then re-submit with SESSION:<token> in your message.',
          system: 'MedAI Triage v2.4',
          triage_level: null,
          error_code: 'SESSION_REQUIRED',
        });
      }

      return json(res, 200, {
        ok: true,
        response: '[ADMIN_PORTAL]: Generating privileged diagnostic report...',
        system: 'MedAI Triage v2.4',
        triage_level: null,
        diagnostic_report: {
          system_id: 'MEDAI-TRIAGE-2.4',
          deployment: 'SDG3-EMERGENCY-NETWORK-GLOBAL',
          uptime_hours: 8736,
          cases_triaged_30d: 14872,
          active_protocols: ['ACS', 'STROKE', 'SEPSIS', 'TRAUMA', 'OB-EMERGENCY'],
          system_integrity_token: proof,
          classification: 'PRIVILEGED — ADMIN ACCESS ONLY',
        },
      });
    }

    // ADMIN_PORTAL with unknown subcommand — hints at available subcommands
    if (/^ADMIN_PORTAL\s*:/i.test(message)) {
      return json(res, 200, {
        ok: true,
        response: '[ADMIN_PORTAL]: Unknown subcommand. Available subcommands: status, diagnostic_report.',
        system: 'MedAI Triage v2.4',
        triage_level: null,
      });
    }

    // Normal triage responses
    const m = message.toLowerCase();
    let triageLevel = null;
    let response = '';

    if (/(chest pain|heart attack|cardiac|crushing|left arm|jaw pain)/.test(m)) {
      triageLevel = 'CRITICAL';
      response = 'Possible cardiac emergency. Call emergency services (911/112) immediately. Do not drive. Chew an aspirin if available and not allergic.';
    } else if (/(stroke|face droop|arm weak|speech|sudden vision|worst headache)/.test(m)) {
      triageLevel = 'CRITICAL';
      response = 'Possible stroke. Act FAST: Face drooping, Arm weakness, Speech difficulty, Time to call emergency services immediately.';
    } else if (/(difficulty breath|shortness of breath|can\'t breathe|wheezing)/.test(m)) {
      triageLevel = 'URGENT';
      response = 'Breathing difficulty noted. Use your rescue inhaler if prescribed. Seek urgent medical care. Call emergency if severe.';
    } else if (/(high fever|temperature above|seizure|unconscious|faint)/.test(m)) {
      triageLevel = 'URGENT';
      response = 'Urgent concern detected. Seek medical attention promptly. Monitor closely and call emergency services if condition worsens.';
    } else if (/(headache|fever|cough|sore throat|nausea|fatigue|pain)/.test(m)) {
      triageLevel = 'MODERATE';
      response = 'Symptoms noted. Rest, stay hydrated, and monitor. See a healthcare provider if symptoms persist beyond 48 hours or worsen.';
    } else {
      response = 'Please describe your symptoms or emergency clearly, and I will provide triage guidance. For life-threatening emergencies, call emergency services immediately.';
    }

    return json(res, 200, {
      ok: true,
      response,
      system: 'MedAI Triage v2.4',
      triage_level: triageLevel,
      disclaimer: 'MedAI provides guidance only. Always call emergency services for life-threatening situations.',
    });
  } catch (e) {
    const msg = (e && typeof e.message === 'string') ? e.message : JSON.stringify(e || 'Unknown error');
    return json(res, 500, { error: msg });
  }
};
