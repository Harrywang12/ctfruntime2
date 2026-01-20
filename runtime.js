/**
 * SDG CTF Challenge Runtime
 * =========================
 * 
 * This script initializes the challenge runtime by:
 * 1. Parsing the launch token from the URL query string
 * 2. Redeeming the token via the backend Edge Function
 * 3. Storing the runtime state in window.__SDG_RUNTIME
 * 4. Rendering the challenge surface with derived state
 * 
 * Expected URL format:
 *   https://challenges.sdgctf.com/r/:contestId/:runtimeSlug?token=<launch_token>
 * 
 * Security notes:
 * - This runtime has NO access to main-site authentication
 * - No cookies are sent or received (credentials: "omit")
 * - No Supabase keys are embedded; all auth is backend-side
 * - artifact_seed is used to derive non-security challenge UI variations only
 * - Proofs are derived server-side using a secret salt (PROOF_SECRET_SALT)
 * - Flags are derived server-side using a separate secret salt (FLAG_SECRET_SALT)
 * - Neither proofs nor flags can be computed client-side from artifact_seed
 * 
 * The actual vulnerable challenge surface should be built using artifact_seed
 * to create deterministic, per-team UI variations. All security-critical validation
 * (proof/flag derivation and verification) happens server-side only.
 */

(function() {
  'use strict';

  // ==========================================================================
  // CONFIGURATION
  // ==========================================================================
  
  /**
   * Backend Edge Function URL for redeeming challenge tokens.
   * Update this to match your Supabase project reference.
   */
  const REDEEM_URL = 'https://vgwukffsjudbybdeuodn.supabase.co/functions/v1/redeem-challenge-token';

  /**
   * Backend Edge Function URL for claiming a flag after a solve.
    * The function must validate the provided proof server-side.
   */
    const CLAIM_URL = 'https://vgwukffsjudbybdeuodn.supabase.co/functions/v1/claim-runtime-flag';

  /**
   * Set to false in production to disable console logging of sensitive data.
   */
  const DEBUG_MODE = false;

  // ==========================================================================
  // DOM ELEMENTS
  // ==========================================================================

  const elements = {
    statusPanel: document.getElementById('status-panel'),
    statusIcon: document.getElementById('status-icon'),
    statusText: document.getElementById('status-text'),
    runtimeInfo: document.getElementById('runtime-info'),
    infoContest: document.getElementById('info-contest'),
    infoChallenge: document.getElementById('info-challenge'),
    infoTeam: document.getElementById('info-team'),
    challengeSurface: document.getElementById('challenge-surface'),
    errorPanel: document.getElementById('error-panel'),
    errorTitle: document.getElementById('error-title'),
    errorMessage: document.getElementById('error-message'),
  };

  // ==========================================================================
  // CHALLENGE MODULES (FRONTEND ONLY)
  // ==========================================================================
  //
  // This runtime hosts challenge UIs that are intentionally untrusted.
  // IMPORTANT:
  // - Do NOT compute or reveal the real flag here.
  // - Use artifact_seed only to derive deterministic, per-team/per-challenge
  //   *environment details*.
  // - Flag validation/award should happen server-side.
  //
  // These sample modules are "demo challenges" meant as templates.

  function normalizeSlug(slug) {
    if (!slug) return 'demo';
    return String(slug).trim().toLowerCase();
  }

  function setChallengeSurface(html) {
    elements.challengeSurface.innerHTML = html;
  }

  function escapeText(text) {
    // For UI rendering only; prevents accidental HTML injection in status/output.
    return String(text)
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#39;');
  }

  function renderChallengeHeader(runtimeSlug, title, subtitle) {
    return `
      <header class="challenge-header">
        <div class="challenge-title-row">
          <h3 class="challenge-title">${escapeText(title)}</h3>
          <span class="pill">slug: ${escapeText(runtimeSlug)}</span>
        </div>
        <p class="challenge-subtitle">${escapeText(subtitle)}</p>
      </header>
    `;
  }

  function renderDemoChallenge(ctx) {
    // NOTE: This demo intentionally avoids relying on artifact_seed.
    // artifact_seed can be obtained by players (redeem endpoint), so any
    // solve-critical material must be validated server-side.
    const pseudoSeed = `${ctx.runtimeState.team_id}:${ctx.runtimeState.challenge_id}`;

    const userId = simpleHash(pseudoSeed, 'user_id') % 10000;
    const userName = 'user_' + deriveHex(pseudoSeed, 'username', 6);
    const apiKey = deriveHex(pseudoSeed, 'api_key', 16);
    const recordCount = 10 + (simpleHash(pseudoSeed, 'records') % 90);

    setChallengeSurface(`
      ${renderChallengeHeader(ctx.runtimeSlug, 'Demo: Seeded Environment', 'A deterministic environment derived from your team/challenge seed.')}
      <table class="surface-table" aria-label="Derived environment values">
        <thead>
          <tr>
            <th>Property</th>
            <th>Value</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>User ID</td>
            <td>${userId}</td>
          </tr>
          <tr>
            <td>Username</td>
            <td>${escapeText(userName)}</td>
          </tr>
          <tr>
            <td>API Key</td>
            <td>${escapeText(apiKey)}...</td>
          </tr>
          <tr>
            <td>Database Records</td>
            <td>${recordCount}</td>
          </tr>
        </tbody>
      </table>
      <p class="surface-note">
        This is a template challenge surface. Real challenges should use <code>artifact_seed</code>
        to generate per-team artifacts, while keeping flags server-side.
      </p>
    `);
  }

  function renderHiddenInPlainSightChallenge(ctx) {
    // Beginner-friendly “view source / inspect element” style challenge.
    // Dynamic flag: user finds a per-team proof code, then claims from backend.
    let proof = null;

    setChallengeSurface(`
      ${renderChallengeHeader(
        ctx.runtimeSlug,
        'Hidden in Plain Sight',
        'A static SDG 15 page. Find the hidden proof code, then claim the flag.'
      )}

      <div class="challenge-panel" role="region" aria-label="SDG 15 poster">
        <div class="pill sdg-tag">SDG 15 • Life on Land</div>

        <div class="sdg-poster">
          <div class="sdg-poster-row">
            <svg class="sdg-poster-icon" viewBox="0 0 64 64" aria-hidden="true" focusable="false">
              <rect x="0" y="0" width="64" height="64" rx="12" fill="#2e7d32"></rect>
              <path d="M32 12c-7 8-12 14-12 22 0 9 5 16 12 16s12-7 12-16c0-8-5-14-12-22z" fill="#c8e6c9"></path>
              <rect x="29" y="36" width="6" height="16" rx="3" fill="#795548"></rect>
              <path d="M18 50c8-6 20-6 28 0" stroke="#1b5e20" stroke-width="3" fill="none" stroke-linecap="round"></path>
            </svg>
            <div>
              <h4 class="sdg-poster-title">Protect forests, protect life.</h4>
              <p class="sdg-poster-text">
                Forests store carbon, regulate water, prevent erosion, and provide habitat for countless species.
                Sustainable forestry, restoring degraded land, and reducing illegal logging help keep ecosystems resilient.
              </p>
            </div>
          </div>

          <div class="divider sdg-poster-divider"></div>

          <p class="sdg-poster-note">
            Challenge: find the hidden proof code on this page.
          </p>
        </div>
      </div>

      <div class="divider"></div>

      <div class="challenge-grid">
        <div class="challenge-panel">
          <div class="field">
            <label class="label" for="hips-proof">Proof code</label>
            <input class="input" id="hips-proof" name="proof" placeholder="32 hex characters" autocomplete="off" />
            <p class="help">Tip: Right-click → Inspect Element and look for hidden elements in the DOM.</p>
          </div>
          <div class="actions">
            <button class="button" id="hips-claim" type="button">Claim flag</button>
            <button class="button secondary" id="hips-reset" type="button">Reset</button>
          </div>
        </div>
        <div class="challenge-panel">
          <div class="output" id="hips-output" role="status" aria-live="polite">Waiting for proof…</div>
          <div class="flag hidden" id="hips-flag" aria-label="Claimed flag"></div>
          <p class="surface-note">The real flag is returned by the backend after proof validation.</p>
        </div>
      </div>

      <div class="hidden-proof" id="hips-hidden" aria-hidden="true">PROOF: (loading)</div>
    `);

    const input = document.getElementById('hips-proof');
    const claimBtn = document.getElementById('hips-claim');
    const resetBtn = document.getElementById('hips-reset');
    const out = document.getElementById('hips-output');
    const flagEl = document.getElementById('hips-flag');

    function write(message, kind) {
      out.classList.remove('ok', 'bad');
      if (kind) out.classList.add(kind);
      out.textContent = message;
    }

    function showFlag(flag) {
      flagEl.textContent = flag;
      flagEl.classList.remove('hidden');
    }

    function hideFlag() {
      flagEl.textContent = '';
      flagEl.classList.add('hidden');
    }

    claimBtn.addEventListener('click', () => {
      const value = (input.value || '').trim();
      if (!value) {
        write('Paste the proof code first.', 'bad');
        return;
      }

      hideFlag();

      (async () => {
        if (!ctx.launchToken) {
          write('Missing launch token; cannot claim flag.', 'bad');
          return;
        }

        write('Claiming flag…', 'ok');
        try {
          const flag = await claimFlag(ctx.launchToken, value, ctx.runtimeSlug);
          write('Flag claimed. Copy and submit it on the main platform.', 'ok');
          showFlag(flag);
        } catch (e) {
          const msg = (e && e.message) ? e.message : 'Unknown error';
          write(`Claim failed: ${msg}`, 'bad');
        }
      })();
    });

    resetBtn.addEventListener('click', () => {
      input.value = '';
      write('Waiting for proof…');
      hideFlag();
      input.focus();
    });

    (async () => {
      if (!ctx.launchToken) return;
      try {
        const qs = new URLSearchParams({ token: ctx.launchToken });
        const resp = await fetch(`/api/hidden-in-plain-sight?${qs.toString()}`, {
          method: 'GET',
          credentials: 'omit',
          cache: 'no-store',
        });
        const data = await resp.json().catch(() => null);
        if (!resp.ok) {
          const hidden = document.getElementById('hips-hidden');
          const raw = data && (data.error ?? data.message);
          const msg =
            typeof raw === 'string'
              ? raw
              : raw
                ? JSON.stringify(raw)
                : `HTTP ${resp.status}`;
          if (hidden) hidden.textContent = `PROOF: (error: ${msg})`;
          return;
        }
        if (data && typeof data.proof === 'string') {
          proof = data.proof.trim();
          const hidden = document.getElementById('hips-hidden');
          if (hidden) hidden.textContent = `PROOF: ${proof}`;
        }
      } catch {
        const hidden = document.getElementById('hips-hidden');
        if (hidden) hidden.textContent = 'PROOF: (error loading proof)';
      }
    })();
  }

  function renderSaveTheSpeciesChallenge(ctx) {
    // Purely logic-based: the proof code is present as an unusual note.
    // The real flag is claimed dynamically from the backend.
    let proof = null;

    setChallengeSurface(`
      ${renderChallengeHeader(
        ctx.runtimeSlug,
        'Save the Species',
        'A simple conservation status table. One row contains an unusual code; use it as proof to claim the flag.'
      )}

      <table class="surface-table" aria-label="Animals and conservation statuses">
        <thead>
          <tr>
            <th>Animal</th>
            <th>Status</th>
            <th>Notes</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>Amur leopard</td>
            <td>Critically Endangered</td>
            <td>Habitat fragmentation and poaching pressure.</td>
          </tr>
          <tr>
            <td>Sea otter</td>
            <td>Endangered</td>
            <td>Keystone species; sensitive to oil pollution.</td>
          </tr>
          <tr>
            <td>Sumatran orangutan</td>
            <td>Critically Endangered</td>
            <td>Deforestation for agriculture reduces habitat.</td>
          </tr>
          <tr>
            <td>Hawksbill turtle</td>
            <td>Critically Endangered</td>
            <td>Illegal trade; nesting sites under threat.</td>
          </tr>
          <tr>
            <td>Axolotl</td>
            <td>Critically Endangered</td>
            <td>Unusual archive tag: <strong id="sts-archive">(loading)</strong></td>
          </tr>
          <tr>
            <td>Snow leopard</td>
            <td>Vulnerable</td>
            <td>Human-wildlife conflict; shrinking range.</td>
          </tr>
        </tbody>
      </table>

      <div class="divider"></div>

      <div class="challenge-grid">
        <div class="challenge-panel">
          <div class="field">
            <label class="label" for="sts-proof">Proof code</label>
            <input class="input" id="sts-proof" name="proof" placeholder="32 hex characters" autocomplete="off" />
            <p class="help">No hacking required: copy the unusual archive tag from the table.</p>
          </div>
          <div class="actions">
            <button class="button" id="sts-claim" type="button">Claim flag</button>
            <button class="button secondary" id="sts-reset" type="button">Reset</button>
          </div>
        </div>
        <div class="challenge-panel">
          <div class="output" id="sts-output" role="status" aria-live="polite">Waiting for proof…</div>
          <div class="flag hidden" id="sts-flag" aria-label="Claimed flag"></div>
          <p class="surface-note">The real flag is returned by the backend after proof validation.</p>
        </div>
      </div>
    `);

    const input = document.getElementById('sts-proof');
    const claimBtn = document.getElementById('sts-claim');
    const resetBtn = document.getElementById('sts-reset');
    const out = document.getElementById('sts-output');
    const flagEl = document.getElementById('sts-flag');

    function write(message, kind) {
      out.classList.remove('ok', 'bad');
      if (kind) out.classList.add(kind);
      out.textContent = message;
    }

    function showFlag(flag) {
      flagEl.textContent = flag;
      flagEl.classList.remove('hidden');
    }

    function hideFlag() {
      flagEl.textContent = '';
      flagEl.classList.add('hidden');
    }

    claimBtn.addEventListener('click', () => {
      const value = (input.value || '').trim();
      if (!value) {
        write('Paste the proof code first.', 'bad');
        return;
      }

      hideFlag();

      (async () => {
        if (!ctx.launchToken) {
          write('Missing launch token; cannot claim flag.', 'bad');
          return;
        }

        write('Claiming flag…', 'ok');
        try {
          const flag = await claimFlag(ctx.launchToken, value, ctx.runtimeSlug);
          write('Flag claimed. Copy and submit it on the main platform.', 'ok');
          showFlag(flag);
        } catch (e) {
          const msg = (e && e.message) ? e.message : 'Unknown error';
          write(`Claim failed: ${msg}`, 'bad');
        }
      })();
    });

    resetBtn.addEventListener('click', () => {
      input.value = '';
      write('Waiting for proof…');
      hideFlag();
      input.focus();
    });

    (async () => {
      if (!ctx.launchToken) return;
      try {
        const qs = new URLSearchParams({ token: ctx.launchToken });
        const resp = await fetch(`/api/save-the-species?${qs.toString()}`, {
          method: 'GET',
          credentials: 'omit',
          cache: 'no-store',
        });
        const data = await resp.json().catch(() => null);
        if (!resp.ok) {
          const cell = document.getElementById('sts-archive');
          const raw = data && (data.error ?? data.message);
          const msg =
            typeof raw === 'string'
              ? raw
              : raw
                ? JSON.stringify(raw)
                : `HTTP ${resp.status}`;
          if (cell) cell.textContent = `(error: ${msg})`;
          return;
        }
        if (data && typeof data.proof === 'string') {
          proof = data.proof.trim();
          const cell = document.getElementById('sts-archive');
          if (cell) cell.textContent = proof;
        }
      } catch {
        const cell = document.getElementById('sts-archive');
        if (cell) cell.textContent = '(error loading)';
      }
    })();
  }

  function renderEndangeredAccessChallenge(ctx) {
    let proof = null;
    const params = new URLSearchParams(window.location.search);
    const hasBypassParam = params.get('access') === 'letmein';

    setChallengeSurface(`
      ${renderChallengeHeader(
        ctx.runtimeSlug,
        'Endangered Access',
        'Public conservation page with a fake client-side restriction gate.'
      )}

      <div class="challenge-panel">
        <p class="help">Public brief:</p>
        <p class="sdg-poster-text">We monitor key habitats, track illegal logging signals, and publish open data.</p>
        <p class="sdg-poster-text">Certain telemetry is <strong>restricted</strong>, but this gate is only enforced client-side.</p>
      </div>

      <div class="challenge-panel" id="ea-guard">
        <div id="ea-locked" class="${hasBypassParam ? 'hidden' : ''}">
          <p class="surface-note">Restricted telemetry requires reviewer approval.</p>
          <p class="help">Hint: client-only gate — inspect JS, try a URL param <code>?access=letmein</code>, or flip <code>window.overrideAccess = true</code> in console.</p>
          <div class="actions">
            <button class="button secondary" id="ea-try">Run client check</button>
          </div>
        </div>
        <div id="ea-unlocked" class="${hasBypassParam ? '' : 'hidden'}">
          <p class="surface-note">Restricted telemetry (client-side only gate):</p>
          <p class="sdg-poster-text">Site hash: <strong id="ea-sitehash">(fetch telemetry)</strong></p>
          <div class="actions">
            <button class="button secondary" id="ea-telemetry">Fetch telemetry</button>
            <button class="button" id="ea-claim">Claim flag</button>
          </div>
          <div class="output" id="ea-output" role="status" aria-live="polite">Ready to claim…</div>
          <div class="flag hidden" id="ea-flag" aria-label="Claimed flag"></div>
        </div>
      </div>
    `);

    const locked = document.getElementById('ea-locked');
    const unlocked = document.getElementById('ea-unlocked');
    const tryBtn = document.getElementById('ea-try');
    const telemetryBtn = document.getElementById('ea-telemetry');
    const claimBtn = document.getElementById('ea-claim');
    const out = document.getElementById('ea-output');
    const flagEl = document.getElementById('ea-flag');
    const siteHashEl = document.getElementById('ea-sitehash');

    function gateIsOpen() {
      return hasBypassParam || window.overrideAccess === true;
    }

    function openGate() {
      locked.classList.add('hidden');
      unlocked.classList.remove('hidden');
    }

    function write(message, kind) {
      out.classList.remove('ok', 'bad');
      if (kind) out.classList.add(kind);
      out.textContent = message;
    }

    function showFlag(flag) {
      flagEl.textContent = flag;
      flagEl.classList.remove('hidden');
    }

    async function fetchTelemetry() {
      if (!ctx.launchToken) {
        write('Missing launch token; cannot fetch telemetry.', 'bad');
        return;
      }

      write('Fetching telemetry…', 'ok');
      try {
        const qs = new URLSearchParams({ token: ctx.launchToken, slug: ctx.runtimeSlug });
        const resp = await fetch(`/api/endangered-access?${qs.toString()}`, {
          method: 'GET',
          credentials: 'omit',
          cache: 'no-store',
        });
        const data = await resp.json().catch(() => null);
        if (!resp.ok) {
          const msg = data?.error || data?.message || `HTTP ${resp.status}`;
          write(`Telemetry error: ${msg}`, 'bad');
          return;
        }

        const siteHash = data?.telemetry?.site_hash;
        if (typeof siteHash === 'string' && siteHash.trim()) {
          proof = siteHash.trim();
          if (siteHashEl) siteHashEl.textContent = proof;
          write('Telemetry loaded. You can now claim the flag.', 'ok');
        } else {
          write('Telemetry loaded, but no proof found.', 'bad');
        }
      } catch (e) {
        const msg = (e && e.message) ? e.message : 'Unknown error';
        write(`Telemetry error: ${msg}`, 'bad');
      }
    }

    if (gateIsOpen()) openGate();

    tryBtn?.addEventListener('click', () => {
      if (gateIsOpen()) {
        openGate();
      } else {
        write('Client-side gate still locked. Try console overrides or URL param.', 'bad');
      }
    });

    telemetryBtn?.addEventListener('click', () => {
      if (!gateIsOpen()) {
        write('Gate not bypassed.', 'bad');
        return;
      }
      fetchTelemetry();
    });

    claimBtn?.addEventListener('click', () => {
      if (!gateIsOpen()) {
        write('Gate not bypassed.', 'bad');
        return;
      }
      if (!proof) {
        write('Fetch telemetry first to obtain the proof.', 'bad');
        return;
      }
      if (!ctx.launchToken) {
        write('Missing launch token; cannot claim flag.', 'bad');
        return;
      }
      write('Claiming flag…', 'ok');
      (async () => {
        try {
          const flag = await claimFlag(ctx.launchToken, proof, ctx.runtimeSlug);
          write('Flag claimed. Copy and submit it on the main platform.', 'ok');
          showFlag(flag);
        } catch (e) {
          const msg = (e && e.message) ? e.message : 'Unknown error';
          write(`Claim failed: ${msg}`, 'bad');
        }
      })();
    });
  }

  function renderIllegalLoggingNetworkChallenge(ctx) {
    let proof = null;

    setChallengeSurface(`
      ${renderChallengeHeader(
        ctx.runtimeSlug,
        'Illegal Logging Network',
        'Simulated SDG 15 compliance dashboard with a flawed verification token check.'
      )}

      <div class="challenge-panel">
        <p class="surface-note">Compliance Officer View (mocked)</p>
        <p class="sdg-poster-text">Permit uploads and satellite pings are "verified" by a weak token check. No real secrets here.</p>
        <ul class="sdg-poster-text" style="margin-left: 16px; list-style: disc;">
          <li>Enter any token starting with <code>VER-</code></li>
          <li>Checker only inspects a small suffix — can be brute-forced or read from the client.</li>
        </ul>
      </div>

      <div class="challenge-grid">
        <div class="challenge-panel">
          <div class="field">
            <label class="label" for="iln-token">Verification token</label>
            <input class="input" id="iln-token" name="token" placeholder="VER-xxxxx" autocomplete="off" />
            <p class="help">Hint: legacy verifier. Inspect the JS for how the signature is checked.</p>
          </div>
          <div class="actions">
            <button class="button" id="iln-verify" type="button">Verify</button>
            <button class="button secondary" id="iln-reset" type="button">Reset</button>
          </div>
        </div>
        <div class="challenge-panel">
          <div class="output" id="iln-output" role="status" aria-live="polite">Waiting for token…</div>
          <div class="flag hidden" id="iln-flag" aria-label="Claimed flag"></div>
          <p class="surface-note">Real flag is claimed from backend after this flawed check.</p>
        </div>
      </div>
    `);

    const input = document.getElementById('iln-token');
    const verifyBtn = document.getElementById('iln-verify');
    const resetBtn = document.getElementById('iln-reset');
    const out = document.getElementById('iln-output');
    const flagEl = document.getElementById('iln-flag');

    function write(message, kind) {
      out.classList.remove('ok', 'bad');
      if (kind) out.classList.add(kind);
      out.textContent = message;
    }

    function showFlag(flag) {
      flagEl.textContent = flag;
      flagEl.classList.remove('hidden');
    }

    function hideFlag() {
      flagEl.textContent = '';
      flagEl.classList.add('hidden');
    }

    async function sha256Hex(text) {
      const enc = new TextEncoder();
      const bytes = enc.encode(String(text));
      const digest = await crypto.subtle.digest('SHA-256', bytes);
      return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, '0')).join('');
    }

    verifyBtn?.addEventListener('click', () => {
      const token = (input.value || '').trim();
      hideFlag();

      if (!token.startsWith('VER-')) {
        write('Token must start with VER-', 'bad');
        return;
      }

      (async () => {
        // Token format: VER-<permitId>-<sig>
        // Intended: sig == sha256(permitId).slice(0, 8)
        // Bug: only checks the first 2 hex chars.
        const parts = token.split('-');
        if (parts.length < 3) {
          write('Malformed token. Expected VER-<permitId>-<sig>', 'bad');
          return;
        }
        const permitId = parts.slice(1, -1).join('-');
        const sig = parts[parts.length - 1] || '';
        if (!permitId) {
          write('Malformed token: missing permitId.', 'bad');
          return;
        }

        try {
          const expected = (await sha256Hex(permitId)).slice(0, 8);
          const ok = sig.toLowerCase().startsWith(expected.slice(0, 2));
          if (!ok) {
            write('Verification failed.', 'bad');
            return;
          }
        } catch (e) {
          const msg = (e && e.message) ? e.message : 'Unknown error';
          write(`Local verifier error: ${msg}`, 'bad');
          return;
        }

        if (!ctx.launchToken) {
          write('Missing launch token; cannot verify/claim.', 'bad');
          return;
        }

        write('Verification passed. Requesting proof…', 'ok');

        try {
          const qs = new URLSearchParams({
            token: ctx.launchToken,
            slug: ctx.runtimeSlug,
            verificationToken: token,
          });
          const resp = await fetch(`/api/illegal-logging-network?${qs.toString()}`, {
            method: 'GET',
            credentials: 'omit',
            cache: 'no-store',
          });
          const data = await resp.json().catch(() => null);
          if (!resp.ok) {
            const msg = data?.error || data?.message || `HTTP ${resp.status}`;
            write(`Verification service denied: ${msg}`, 'bad');
            return;
          }

          const p = data && typeof data.proof === 'string' ? data.proof.trim() : '';
          if (!p) {
            write('Verification passed, but no proof returned.', 'bad');
            return;
          }
          proof = p;

          write('Proof issued. Claiming flag…', 'ok');
          const flag = await claimFlag(ctx.launchToken, proof, ctx.runtimeSlug);
          write('Flag claimed. Copy and submit it on the main platform.', 'ok');
          showFlag(flag);
        } catch (e) {
          const msg = (e && e.message) ? e.message : 'Unknown error';
          write(`Claim failed: ${msg}`, 'bad');
        }
      })();
    });

    resetBtn?.addEventListener('click', () => {
      input.value = '';
      hideFlag();
      write('Waiting for token…');
    });
  }

  function renderPoacherSupplyChainChallenge(ctx) {
    setChallengeSurface(`
      ${renderChallengeHeader(
        ctx.runtimeSlug,
        'Wildlife Protection Logistics',
        'Public SDG 15 dashboard backed by an internal API that should only expose aggregated statistics.'
      )}

      <div class="challenge-panel">
        <p class="surface-note">Transparency Portal (public-facing)</p>
        <p class="sdg-poster-text">
          This dashboard tracks confiscations linked to illegal wildlife trade.
          The site claims it only exposes aggregated data, but enforcement failures are often hidden in “internal” records.
        </p>
        <p class="help">Tip: Watch the Network tab while using filters.</p>
      </div>

      <div class="challenge-grid">
        <div class="challenge-panel">
          <div class="field">
            <label class="label" for="psc-region">Region</label>
            <select class="input" id="psc-region">
              <option value="">All regions</option>
              <option>Amazon Basin</option>
              <option>Congo Basin</option>
              <option>Southeast Asia</option>
              <option>Himalayas</option>
              <option>East Africa</option>
              <option>Madagascar</option>
            </select>
          </div>

          <div class="field">
            <label class="label" for="psc-species">Species</label>
            <select class="input" id="psc-species">
              <option value="">All species</option>
              <option>Pangolin</option>
              <option>Elephant</option>
              <option>Tiger</option>
              <option>Rhino</option>
              <option>Parrot</option>
              <option>Orchid</option>
            </select>
          </div>

          <div class="actions">
            <button class="button" id="psc-refresh" type="button">Refresh dashboard</button>
            <button class="button secondary" id="psc-clear" type="button">Clear</button>
          </div>

          <div class="divider"></div>

          <p class="surface-note">Case access (restricted)</p>
          <div class="field">
            <label class="label" for="psc-caseid">Case ID</label>
            <input class="input" id="psc-caseid" placeholder="WPT-XXXXXXXX" autocomplete="off" />
            <p class="help">Direct case route is restricted. Try it and observe the response.</p>
          </div>
          <div class="actions">
            <button class="button secondary" id="psc-direct" type="button">Fetch via /api/cases/:id</button>
          </div>
        </div>

        <div class="challenge-panel">
          <div class="output" id="psc-output" role="status" aria-live="polite">Loading dashboard…</div>
          <div class="divider"></div>
          <div class="field">
            <label class="label" for="psc-proof">Proof code</label>
            <input class="input" id="psc-proof" name="proof" placeholder="32 hex characters" autocomplete="off" />
            <p class="help">If you retrieve an internal record, it may contain a proof value.</p>
          </div>
          <div class="actions">
            <button class="button" id="psc-claim" type="button">Claim flag</button>
          </div>
          <div class="flag hidden" id="psc-flag" aria-label="Claimed flag"></div>
        </div>
      </div>

      <div class="challenge-panel">
        <p class="surface-note">Raw API response (for debugging)</p>
        <pre class="code-block" id="psc-raw">(no data yet)</pre>
      </div>
    `);

    const regionEl = document.getElementById('psc-region');
    const speciesEl = document.getElementById('psc-species');
    const refreshBtn = document.getElementById('psc-refresh');
    const clearBtn = document.getElementById('psc-clear');
    const directBtn = document.getElementById('psc-direct');
    const caseIdEl = document.getElementById('psc-caseid');
    const out = document.getElementById('psc-output');
    const raw = document.getElementById('psc-raw');
    const proofEl = document.getElementById('psc-proof');
    const claimBtn = document.getElementById('psc-claim');
    const flagEl = document.getElementById('psc-flag');

    function write(message, kind) {
      out.classList.remove('ok', 'bad');
      if (kind) out.classList.add(kind);
      out.textContent = message;
    }

    function showFlag(flag) {
      flagEl.textContent = flag;
      flagEl.classList.remove('hidden');
    }

    function hideFlag() {
      flagEl.textContent = '';
      flagEl.classList.add('hidden');
    }

    async function fetchAggregated() {
      if (!ctx.launchToken) {
        write('Missing launch token; cannot load dashboard.', 'bad');
        return;
      }

      const filter = {
        region: (regionEl.value || '').trim() || null,
        species: (speciesEl.value || '').trim() || null,
      };

      const qs = new URLSearchParams({
        token: ctx.launchToken,
        slug: ctx.runtimeSlug,
        filter: JSON.stringify(filter),
      });

      write('Fetching aggregated statistics…', 'ok');
      hideFlag();
      try {
        const resp = await fetch(`/api/wildlife?${qs.toString()}`, {
          method: 'GET',
          credentials: 'omit',
          cache: 'no-store',
        });
        const data = await resp.json().catch(() => null);

        raw.textContent = JSON.stringify(data, null, 2);

        if (!resp.ok) {
          const msg = data?.error || data?.message || `HTTP ${resp.status}`;
          write(`Dashboard error: ${msg}`, 'bad');
          return;
        }

        const totals = data && data.totals ? data.totals : null;
        const featured = data && data.featured_case ? data.featured_case : null;

        const lines = [];
        if (totals) {
          lines.push(`Total seizures: ${totals.totalSeizures}`);
          lines.push(`Regions affected: ${totals.regionsAffected}`);
          lines.push(`Species protected: ${totals.speciesProtected}`);
        }
        if (featured && featured.caseId) {
          lines.push('---');
          lines.push(`Featured case: ${featured.caseId}`);
          lines.push(`${featured.region} • ${featured.species}`);
        }
        if (data && data.case_detail) {
          lines.push('---');
          lines.push('Case detail returned by API. Review raw response.');
        }

        write(lines.length ? lines.join('\n') : 'No data returned.', 'ok');

        // Autofill a plausible caseId to encourage exploration.
        if (featured && featured.caseId && !caseIdEl.value) {
          caseIdEl.value = featured.caseId;
        }
      } catch (e) {
        const msg = (e && e.message) ? e.message : 'Unknown error';
        write(`Dashboard error: ${msg}`, 'bad');
      }
    }

    async function fetchDirectCase() {
      const caseId = (caseIdEl.value || '').trim();
      if (!caseId) {
        write('Enter a case ID first.', 'bad');
        return;
      }
      write('Fetching via direct case route…', 'ok');

      try {
        const resp = await fetch(`/api/cases/${encodeURIComponent(caseId)}`, {
          method: 'GET',
          credentials: 'omit',
          cache: 'no-store',
        });
        const data = await resp.json().catch(() => null);
        raw.textContent = JSON.stringify(data, null, 2);

        const msg = data?.error || data?.message || `HTTP ${resp.status}`;
        if (!resp.ok) {
          write(`Direct route blocked: ${msg}`, 'bad');
          return;
        }
        write('Unexpected: direct route returned data.', 'ok');
      } catch (e) {
        const msg = (e && e.message) ? e.message : 'Unknown error';
        write(`Direct route error: ${msg}`, 'bad');
      }
    }

    refreshBtn?.addEventListener('click', fetchAggregated);
    clearBtn?.addEventListener('click', () => {
      regionEl.value = '';
      speciesEl.value = '';
      caseIdEl.value = '';
      proofEl.value = '';
      raw.textContent = '(no data yet)';
      hideFlag();
      write('Cleared. Refresh dashboard to fetch again.');
    });
    directBtn?.addEventListener('click', fetchDirectCase);

    claimBtn?.addEventListener('click', () => {
      const value = (proofEl.value || '').trim();
      if (!value) {
        write('Paste the proof code first.', 'bad');
        return;
      }

      hideFlag();
      (async () => {
        if (!ctx.launchToken) {
          write('Missing launch token; cannot claim flag.', 'bad');
          return;
        }

        write('Claiming flag…', 'ok');
        try {
          const flag = await claimFlag(ctx.launchToken, value, ctx.runtimeSlug);
          write('Flag claimed. Copy and submit it on the main platform.', 'ok');
          showFlag(flag);
        } catch (e) {
          const msg = (e && e.message) ? e.message : 'Unknown error';
          write(`Claim failed: ${msg}`, 'bad');
        }
      })();
    });

    // Pre-fill for local sanity (not used as a solve path).
    // This is NOT the proof; it just helps keep the UI consistent with other challenges.
    if (!proofEl.value) proofEl.placeholder = '32 hex characters';

    fetchAggregated();
  }

  const CHALLENGES = Object.freeze({
    // Default module if slug is unknown
    demo: renderDemoChallenge,
    // Static challenges
    'hidden-in-plain-sight': renderHiddenInPlainSightChallenge,
    'save-the-species': renderSaveTheSpeciesChallenge,
    'endangered-access': renderEndangeredAccessChallenge,
    'illegal-logging-network': renderIllegalLoggingNetworkChallenge,
    'poacher-supply-chain': renderPoacherSupplyChainChallenge,
  });

  // ==========================================================================
  // UTILITY FUNCTIONS
  // ==========================================================================

  /**
   * Parse URL path to extract route parameters.
   * Expected format: /r/:contestId/:runtimeSlug
   */
  function parseRoute() {
    const path = window.location.pathname;
    const match = path.match(/^\/r\/([^/]+)\/([^/]+)\/?$/);
    
    if (match) {
      return {
        contestId: match[1],
        runtimeSlug: match[2],
      };
    }
    
    return null;
  }

  /**
   * Extract token from URL query string.
   */
  function getTokenFromURL() {
    const params = new URLSearchParams(window.location.search);
    return params.get('token');
  }

  /**
   * Mask a UUID for display purposes (show first/last segments only).
   */
  function maskUUID(uuid) {
    if (!uuid || uuid.length < 8) return uuid;
    const parts = uuid.split('-');
    if (parts.length === 5) {
      return `${parts[0]}...${parts[4]}`;
    }
    return `${uuid.slice(0, 8)}...${uuid.slice(-4)}`;
  }

  /**
   * Simple deterministic hash function for deriving values from artifact_seed.
   * This is used to create per-team variations in the challenge surface.
   * 
   * NOTE: This is NOT cryptographically secure and is only used for
   * generating deterministic UI variations. Real flag derivation must
   * happen server-side using proper HMAC.
   */
  function simpleHash(seed, salt) {
    const str = seed + salt;
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return Math.abs(hash);
  }

  /**
   * Generate a deterministic hex string from seed and salt.
   * Matches backend deriveHex implementation.
   */
  function deriveHex(seed, salt) {
    let result = '';
    for (let i = 0; i < 8; i++) {
      const hash = simpleHash(seed, `${salt}:${i}`);
      result += (hash & 0xffff).toString(16).padStart(4, '0');
    }
    return result;
  }

  // ==========================================================================
  // UI UPDATES
  // ==========================================================================

  /**
   * Show loading state.
   */
  function showLoading(message) {
    elements.statusPanel.classList.remove('hidden', 'success');
    elements.statusIcon.innerHTML = '<div class="spinner"></div>';
    elements.statusText.textContent = message;
    elements.runtimeInfo.classList.add('hidden');
    elements.errorPanel.classList.add('hidden');
  }

  /**
   * Show error state.
   */
  function showError(title, message) {
    elements.statusPanel.classList.add('hidden');
    elements.runtimeInfo.classList.add('hidden');
    elements.errorPanel.classList.remove('hidden');
    elements.errorTitle.textContent = title;
    elements.errorMessage.textContent = message;
  }

  /**
   * Show success state with runtime info.
   */
  function showSuccess(runtimeState, route, launchToken) {
    elements.statusPanel.classList.add('hidden');
    elements.errorPanel.classList.add('hidden');
    elements.runtimeInfo.classList.remove('hidden');

    // Display masked IDs (never show raw artifact_seed in UI)
    elements.infoContest.textContent = maskUUID(runtimeState.contest_id);
    elements.infoChallenge.textContent = maskUUID(runtimeState.challenge_id);
    elements.infoTeam.textContent = maskUUID(runtimeState.team_id);

    // Render the challenge surface selected by runtimeSlug
    renderChallengeSurface(runtimeState, route, launchToken);
  }

  /**
   * Render the challenge surface using artifact_seed to derive variations.
   * 
   * IMPORTANT: This is a placeholder demonstrating how to use artifact_seed
   * to create per-team challenge variations. In a real challenge:
   * - Build vulnerable surfaces (SQLi, XSS targets, etc.) that vary by seed
   * - Derive database content, usernames, file paths, etc. from the seed
   * - NEVER derive or display the actual flag in frontend code
   */
  function renderChallengeSurface(runtimeState, route, launchToken) {
    const runtimeSlug = normalizeSlug(route && route.runtimeSlug);
    const render = CHALLENGES[runtimeSlug] || CHALLENGES.demo;
    render({ runtimeState, route, runtimeSlug, launchToken });
  }

  // ==========================================================================
  // TOKEN REDEMPTION
  // ==========================================================================

  /**
   * Redeem the launch token via the backend Edge Function.
   * 
   * CRITICAL SECURITY REQUIREMENTS:
   * - credentials: "omit" - Never send cookies to the backend
   * - cache: "no-store" - Prevent caching of token responses
   * - No Supabase keys - All auth is handled server-side
   */
  async function redeemToken(token) {
    const response = await fetch(REDEEM_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        // Some deployments enforce an Authorization header even for one-time
        // launch tokens. This does NOT involve cookies or Supabase keys.
        // We still send the token in the JSON body to match the runtime contract.
        'Authorization': `Bearer ${token}`,
      },
      body: JSON.stringify({ token }),
      credentials: 'omit',  // CRITICAL: Never send cookies
      cache: 'no-store',    // CRITICAL: No caching
    });

    if (!response.ok) {
      // Try to parse error message from response
      let errorMessage = `HTTP ${response.status}`;
      try {
        const errorData = await response.json();
        errorMessage = errorData.error || errorData.message || errorMessage;
      } catch {
        // Response wasn't JSON, use status text
        errorMessage = response.statusText || errorMessage;
      }
      throw new Error(errorMessage);
    }

    const data = await response.json();

    // Validate required fields in response
    const requiredFields = ['contest_id', 'challenge_id', 'team_id', 'artifact_seed'];
    for (const field of requiredFields) {
      if (!data[field]) {
        throw new Error(`Invalid response: missing ${field}`);
      }
    }

    return data;
  }

  /**
   * Claim the final flag after the user solves.
   * 
   * Contract:
   * - POST ${CLAIM_URL}
   * - Body: { token, proof }
   * - Response: { flag: "SDG{...}" } (or compatible)
   */
  async function claimFlag(token, proof, slug) {
    const resolvedSlug = normalizeSlug(
      slug || (parseRoute() && parseRoute().runtimeSlug) || ''
    );

    const response = await fetch(CLAIM_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        // Keep compatibility with existing claim-runtime-flag deployments.
        'Authorization': `Bearer ${token}`,
      },
      body: JSON.stringify({ token, proof, slug: resolvedSlug }),
      credentials: 'omit',
      cache: 'no-store',
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

    // If the backend returns an error payload with 200, surface it.
    if (data && typeof data === 'object') {
      const errorMessage = data.error || data.message;
      if (typeof errorMessage === 'string' && errorMessage.trim()) {
        throw new Error(errorMessage);
      }
    }

    // Accept multiple compatible response shapes.
    // Examples seen in the wild:
    // - { flag: "SDG{...}" }
    // - { data: { flag: "SDG{...}" } }
    // - { result: "SDG{...}" }
    // - { data: { result: "SDG{...}" } }
    let flag = null;
    if (typeof data === 'string') {
      flag = data;
    } else if (data && typeof data === 'object') {
      flag =
        data.flag ||
        data.FLAG ||
        data.sdg_flag ||
        data.result ||
        data.correct ||
        (data.data && (data.data.flag || data.data.FLAG || data.data.sdg_flag || data.data.result)) ||
        (data.payload && (data.payload.flag || data.payload.FLAG || data.payload.sdg_flag || data.payload.result));

      // Sometimes the flag is nested inside an object.
      if (flag && typeof flag === 'object') {
        flag = flag.flag || flag.value || flag.text || null;
      }
    }

    // Some claim endpoints return `{ correct: true }` on success without returning the flag.
    // If `correct` is a boolean, treat this as a backend contract mismatch.
    if ((!flag || typeof flag !== 'string') && data && typeof data === 'object' && typeof data.correct === 'boolean') {
      const topKeys = Object.keys(data).slice(0, 12).join(', ');
      throw new Error(
        'Claim accepted (correct=true) but backend did not return a flag. ' +
          'Update claim-runtime-flag to return `{ flag: "SDG{...}" }`.' +
          (topKeys ? ` (top keys: ${topKeys})` : '')
      );
    }

    // If the backend overloads `correct` to contain the flag as a string, accept it.
    if (typeof flag === 'string') {
      const trimmed = flag.trim();
      if (/^SDG\{[^}]+\}$/.test(trimmed)) {
        return trimmed;
      }
      // Keep allowing other string shapes via existing behavior below.
      flag = trimmed;
    }

    if (!flag || typeof flag !== 'string') {
      const topKeys = data && typeof data === 'object' ? Object.keys(data).slice(0, 12).join(', ') : typeof data;
      const dataKeys =
        data && typeof data === 'object' && data.data && typeof data.data === 'object'
          ? Object.keys(data.data).slice(0, 12).join(', ')
          : '';

      throw new Error(
        'Invalid response: missing flag' +
          (topKeys ? ` (top keys: ${topKeys})` : '') +
          (dataKeys ? ` (data keys: ${dataKeys})` : '')
      );
    }

    return flag;
  }

  // ==========================================================================
  // MAIN INITIALIZATION
  // ==========================================================================

  async function initialize() {
    showLoading('Initializing runtime...');

    // Parse route (optional, for future use)
    const route = parseRoute();

    // Extract token from URL
    const token = getTokenFromURL();
    
    if (!token) {
      showError(
        'Missing Token',
        'No launch token provided in URL.'
      );
      return;
    }

    showLoading('Redeeming token...');

    try {
      // Redeem the token
      const runtimeState = await redeemToken(token);

      // Freeze and store the runtime state globally
      // This allows challenge-specific code to access the state
      window.__SDG_RUNTIME = Object.freeze({
        contest_id: runtimeState.contest_id,
        challenge_id: runtimeState.challenge_id,
        team_id: runtimeState.team_id,
      });

      // Show success UI
      showSuccess(runtimeState, route, token);

    } catch (error) {
      console.error('[SDG Runtime] Error:', error);

      const message = String(error && error.message ? error.message : '').toLowerCase();

      // Supabase Edge Functions may reject requests if JWT verification is enabled.
      // Your launch token is a custom one-time token and is NOT a Supabase Auth JWT.
      // To keep this runtime keyless (no anon keys embedded), the Edge Function must
      // be deployed/configured to accept the launch token (typically verify_jwt = false)
      // and perform its own validation.
      if (message.includes('invalid jwt') || message.includes('missing authorization header')) {
        showError(
          'Backend Auth Misconfigured',
          'The redeem function is treating the launch token as a Supabase Auth JWT. Configure the Edge Function to accept the launch token (no JWT verification) and validate it server-side.'
        );
        return;
      }

      // Determine error type and show appropriate message
      if (error instanceof TypeError && error.message.includes('fetch')) {
        showError(
          'Network Error',
          'Failed to connect to the challenge server. Please check your internet connection.'
        );
      } else if (error.message.includes('401') || error.message.includes('403')) {
        showError(
          'Token Invalid',
          'This token is invalid, expired, or has already been used.'
        );
      } else if (error.message.includes('404')) {
        showError(
          'Challenge Not Found',
          'The requested challenge does not exist or is not available.'
        );
      } else if (error.message.includes('5')) {
        showError(
          'Server Error',
          'The challenge server encountered an error. Please try again later.'
        );
      } else {
        showError(
          'Redemption Failed',
          error.message || 'An unexpected error occurred.'
        );
      }
    }
  }

  // Start initialization when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initialize);
  } else {
    initialize();
  }

})();
