
const crypto = require('crypto');
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

function deriveJwtSecret(seed) {
  let result = '';
  for (let i = 0; i < 4; i++) {
    const hash = simpleHash(seed, `medfed_jwt_secret:${i}`);
    result += (hash >>> 0).toString(16).padStart(8, '0');
  }
  return result; // 32 hex chars, deterministic per seed
}

function b64url(str) {
  return Buffer.from(str, 'utf8').toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function b64urlDecode(str) {
  const padded = str + '='.repeat((4 - (str.length % 4)) % 4);
  return Buffer.from(padded.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
}

function verifyJwt(token, secret) {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  try {
    const header = JSON.parse(b64urlDecode(parts[0]));
    const payload = JSON.parse(b64urlDecode(parts[1]));
    if (header.alg !== 'HS256') return null;
    const expected = crypto.createHmac('sha256', secret)
      .update(`${parts[0]}.${parts[1]}`)
      .digest('base64')
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    if (expected !== parts[2]) return null;
    return payload;
  } catch { return null; }
}

// Simulated internal network — not reachable via normal proxy allowlist
function simulateInternalFetch(hostname, pathname, searchParams, seed) {
  if (hostname === 'admin-portal.mednet.local') {
    const token = (searchParams && searchParams.get('token')) || '';
    if (!token) {
      return { status: 400, body: { error: 'Missing token parameter. Include ?token=<jwt> in the URL.' } };
    }
    const jwtSecret = deriveJwtSecret(seed);
    const payload = verifyJwt(token, jwtSecret);
    if (!payload) {
      return { status: 401, body: { error: 'Invalid or malformed JWT.' } };
    }
    if (payload.role !== 'medfed_admin') {
      return { status: 403, body: { error: 'Insufficient role. medfed_admin required.', your_role: payload.role || null } };
    }
    const proof = computeProof({ artifactSeed: seed, runtimeSlug: 'clinical-gateway-ssrf' });
    return {
      status: 200,
      body: {
        ok: true,
        system: 'MedFed Admin Portal',
        message: 'Admin access granted. SDG 3 research network operational.',
        network_integrity_token: proof,
        classification: 'PRIVILEGED — ADMIN ACCESS ONLY',
      },
    };
  }

  if (hostname === 'internal-config.mednet.local') {
    if (pathname === '/' || pathname === '') {
      return {
        status: 200,
        body: {
          service: 'MedFed Internal Config Service',
          version: '1.2',
          endpoints: ['/health', '/secrets'],
          note: 'Internal use only. Access from external networks is not permitted.',
        },
      };
    }
    if (pathname === '/secrets') {
      const jwtSecret = deriveJwtSecret(seed);
      return {
        status: 200,
        body: {
          _classification: 'INTERNAL — NOT FOR EXTERNAL ACCESS',
          service: 'MedFed API Config Service v1.2',
          environment: 'production',
          jwt_signing_secret: jwtSecret,
          admin_role: 'medfed_admin',
          token_expiry_seconds: 3600,
        },
      };
    }
    if (pathname === '/health') {
      return { status: 200, body: { status: 'healthy', uptime_hours: 4320 } };
    }
    return { status: 404, body: { error: 'Not found' } };
  }

  if (hostname === 'health-api.who.int') {
    return {
      status: 200,
      body: {
        source: 'WHO Global Health Observatory',
        datasets: ['mortality', 'disease-burden', 'health-systems', 'sdg3-indicators'],
        sdg3_coverage: '194 member states',
        access: 'public',
      },
    };
  }

  return null;
}

module.exports = async function handler(req, res) {
  try {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const seed = url.searchParams.get('seed') || '';
    const action = url.searchParams.get('action') || 'info';

    if (!seed || !/^[0-9a-f]{64}$/i.test(String(seed))) {
      return json(res, 400, { error: 'Missing or invalid seed' });
    }

    if (action === 'info') {
      return json(res, 200, {
        ok: true,
        system: 'MedFed API Gateway v3.0',
        description: 'Federated health data gateway for the SDG 3 research network. Proxies requests to approved WHO health data sources.',
        architecture: {
          public_layer: 'This gateway (external-facing)',
          config_layer: 'internal-config.mednet.local — configuration and secret management (internal network only)',
          admin_layer: 'admin-portal.mednet.local — privileged admin operations (internal only)',
        },
        endpoints: {
          proxy: '?action=proxy&url=<url> — proxy a request to an allowlisted health data URL',
        },
        proxy_allowlist: 'Only health-api.who.int endpoints are permitted.',
        admin_note: 'Admin operations are only accessible via the internal network through the proxy.',
      });
    }

    if (action === 'proxy') {
      const proxyUrl = url.searchParams.get('url') || '';
      if (!proxyUrl) return json(res, 400, { error: 'Missing url parameter.' });

      // VULNERABILITY: naive string inclusion check — bypassable with URL userinfo injection
      // e.g. http://health-api.who.int@internal-config.mednet.local/secrets
      // The string "health-api.who.int" is present, so the check passes,
      // but new URL() correctly parses internal-config.mednet.local as the hostname.
      if (!proxyUrl.includes('health-api.who.int')) {
        return json(res, 403, {
          error: 'URL not in allowlist. Only health-api.who.int endpoints are permitted.',
        });
      }

      let parsedUrl;
      try {
        parsedUrl = new URL(proxyUrl);
      } catch {
        return json(res, 400, { error: 'Invalid URL format.' });
      }

      const result = simulateInternalFetch(parsedUrl.hostname, parsedUrl.pathname, parsedUrl.searchParams, seed);
      if (!result) {
        return json(res, 502, {
          error: `Host ${parsedUrl.hostname} is not reachable from this gateway.`,
        });
      }

      return json(res, result.status, {
        ok: result.status === 200,
        proxied_url: proxyUrl,
        status: result.status,
        response: result.body,
      });
    }

    if (action === 'admin') {
      return json(res, 403, {
        ok: false,
        error: 'Access denied. The admin portal is restricted to internal network requests.',
        hint: 'Route your request through the proxy to reach admin-portal.mednet.local.',
      });
    }

    return json(res, 400, { error: 'Unknown action. Use: info, proxy, admin' });
  } catch (e) {
    const msg = (e && typeof e.message === 'string') ? e.message : JSON.stringify(e || 'Unknown error');
    return json(res, 500, { error: msg });
  }
};
