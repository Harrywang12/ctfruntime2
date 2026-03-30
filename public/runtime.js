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
 * Expected URL formats:
 *   https://challenges.sdgctf.com/r/:contestId/:runtimeSlug?token=<launch_token>  (contest)
 *   https://challenges.sdgctf.com/r/:runtimeSlug?token=<launch_token>              (practice)
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

(function () {
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

  function renderHints(hints) {
    if (!hints || !hints.length) return '';
    return `
      <div class="hints-section">
        <div class="hint-header">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"></path><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>
          HINTS (${hints.length})
        </div>
        <div class="hint-list" id="hint-list">
          ${hints.map((h, i) => `
            <div class="hint-item ${i === 0 ? '' : 'locked'}" data-index="${i}">
              <button class="hint-reveal-btn ${i === 0 ? '' : 'hidden'}" type="button">Reveal Hint ${i + 1}</button>
              <div class="hint-content hint-blur">${escapeText(h)}</div>
            </div>
          `).join('')}
        </div>
      </div>
    `;
  }

  function setupHintListeners(container) {
    if (!container) return;
    const list = container.querySelector('#hint-list');
    if (!list) return;

    const items = list.querySelectorAll('.hint-item');
    items.forEach((item, index) => {
      const btn = item.querySelector('.hint-reveal-btn');
      const content = item.querySelector('.hint-content');

      if (btn) {
        btn.addEventListener('click', (e) => {
          e.preventDefault();
          e.stopPropagation();
          btn.classList.add('hidden');
          content.classList.remove('hint-blur');
          item.classList.add('visible');
          item.classList.remove('locked');

          if (index < items.length - 1) {
            const nextItem = items[index + 1];
            nextItem.classList.remove('locked');
            const nextBtn = nextItem.querySelector('.hint-reveal-btn');
            if (nextBtn) nextBtn.classList.remove('hidden');
          }
        });
      }
    });
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
    const seedSource = ctx.runtimeState.team_id || ctx.runtimeState.artifact_seed || 'anon';
    const pseudoSeed = `${seedSource}:${ctx.runtimeState.challenge_id}`;

    const userId = simpleHash(pseudoSeed, 'user_id') % 10000;
    const userName = 'user_' + deriveHex(pseudoSeed, 'username', 6);
    const apiKey = deriveHex(pseudoSeed, 'api_key', 16);
    const recordCount = 10 + (simpleHash(pseudoSeed, 'records') % 90);

    setChallengeSurface(`
      <div class="challenge-section">
        ${renderChallengeHeader(ctx.runtimeSlug, 'Demo: Seeded Environment', 'A deterministic environment derived from your team/challenge seed.')}

        <div class="challenge-panel">
          <div class="text-lg font-bold">Objective</div>
          <p class="text-base text-secondary mb-4">Verify that the environment is deterministic and unique to your team.</p>

          <div class="text-lg font-bold">Description</div>
          <p class="text-base text-secondary">This is a demonstration challenge to show how the runtime derives environment details from your seed. It serves as a template for other challenges.</p>
        </div>

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

      </div>
    `);
  }

  // ==========================================================================
  // SDG 3 — GOOD HEALTH AND WELLBEING CHALLENGES
  // ==========================================================================

  // ── Easy 1: Patient Portal Leak ──────────────────────────────────────────
  function renderPatientPortalLeakChallenge(ctx) {
    const hints = [
      'Patient records have states beyond "active" — most APIs reflect what you ask for.',
      'Headers are part of the request contract too, not just query parameters.',
      'Not every feature is advertised in the documentation.',
    ];

    setChallengeSurface(`
      <div class="challenge-section">
        ${renderChallengeHeader(ctx.runtimeSlug, 'Patient Portal Leak', 'SDG 3 — MediConnect Patient Portal')}
        <div class="challenge-panel">
          <div class="text-lg font-bold">Objective</div>
          <p class="text-base text-secondary mb-4">Something in the registry is not being shown. Find out what the portal is keeping from you.</p>
          <div class="text-lg font-bold">Description</div>
          <p class="text-base text-secondary">A routine compliance review flagged unusual discrepancies in MediConnect's patient access logs. The portal was audited and patched — but a field investigator noted that certain records seemed to vanish without explanation. Access has since been restricted to 'active' entries only.</p>
        </div>
        <div class="challenge-panel" style="padding:0;overflow:hidden;">
          <div style="background:#1a2332;border-bottom:1px solid #2a3a4a;padding:10px 16px;display:flex;align-items:center;gap:10px;">
            <span style="font-size:13px;font-weight:600;color:#4fc3f7;letter-spacing:0.05em;">MEDICONNECT</span>
            <span style="font-size:11px;color:#607080;border-left:1px solid #2a3a4a;padding-left:10px;">Patient Portal v2.3</span>
          </div>
          <div style="padding:16px;">
            <div class="actions">
              <button class="button secondary" id="ppl-fetch" type="button">Fetch Patients</button>
            </div>
            <div class="divider"></div>
            <p class="surface-note">Patient List</p>
            <div id="ppl-table" style="margin-bottom:8px;"></div>
            <pre class="code-block" id="ppl-raw" style="min-height:80px;display:none;">(no data yet)</pre>
          </div>
        </div>
        <div class="challenge-grid">
          <div class="challenge-panel">
            <div class="field">
              <label class="label" for="ppl-proof">Proof code</label>
              <input class="input" id="ppl-proof" name="proof" placeholder="32 hex characters" autocomplete="off" />
            </div>
            <div class="actions">
              <button class="button" id="ppl-claim" type="button">Claim flag</button>
            </div>
          </div>
          <div class="challenge-panel">
            <div class="output" id="ppl-output" role="status" aria-live="polite">Waiting for proof...</div>
            <div class="flag hidden" id="ppl-flag" aria-label="Claimed flag"></div>
          </div>
        </div>
        ${renderHints(hints)}
      </div>
    `);

    setupHintListeners(elements.challengeSurface);

    const raw = document.getElementById('ppl-raw');
    const tableDiv = document.getElementById('ppl-table');
    const out = document.getElementById('ppl-output');
    const flagEl = document.getElementById('ppl-flag');
    const proofEl = document.getElementById('ppl-proof');
    const fetchBtn = document.getElementById('ppl-fetch');
    const claimBtn = document.getElementById('ppl-claim');

    function write(m, k) { out.classList.remove('ok', 'bad'); if (k) out.classList.add(k); out.textContent = m; }
    function showFlag(f) { flagEl.textContent = f; flagEl.classList.remove('hidden'); }
    function hideFlag() { flagEl.textContent = ''; flagEl.classList.add('hidden'); }

    function renderTable(patients) {
      if (!patients || !patients.length) { tableDiv.innerHTML = '<p class="surface-note">No patients returned.</p>'; return; }
      const cols = Object.keys(patients[0]);
      const thead = '<tr>' + cols.map(c => `<th>${escapeText(c)}</th>`).join('') + '</tr>';
      const tbody = patients.map(p => '<tr>' + cols.map(c => `<td>${escapeText(String(p[c] ?? ''))}</td>`).join('') + '</tr>').join('');
      tableDiv.innerHTML = `<table class="surface-table">${thead}${tbody}</table>`;
    }

    fetchBtn?.addEventListener('click', async () => {
      const qs = new URLSearchParams({ seed: ctx.runtimeState.artifact_seed });
      try {
        const resp = await fetch('/api/patient-portal-leak?' + qs, { credentials: 'omit', cache: 'no-store' });
        const data = await resp.json().catch(() => null);
        raw.textContent = JSON.stringify(data, null, 2);
        if (data?.patients) renderTable(data.patients);
        const auditToken = data?.patients?.find(p => p.audit_token)?.audit_token;
        if (auditToken) { proofEl.value = auditToken; write('Audit token found!', 'ok'); }
        else { write(resp.ok ? 'Data loaded. Look for hidden parameters.' : 'Error: ' + (data?.error || resp.status), resp.ok ? 'ok' : 'bad'); }
      } catch (e) { write('Error: ' + e.message, 'bad'); }
    });

    claimBtn?.addEventListener('click', () => {
      const v = (proofEl.value || '').trim(); if (!v) { write('Paste proof first.', 'bad'); return; } hideFlag();
      (async () => { try { const flag = await claimFlag(ctx.launchToken, v, ctx.runtimeSlug); write('Flag claimed.', 'ok'); showFlag(flag); } catch (e) { write('Claim failed: ' + e.message, 'bad'); } })();
    });
  }

  // ── Easy 2: Vaccine Cold Chain ───────────────────────────────────────────
  function renderVaccineColdChainChallenge(ctx) {
    const hints = [
      'Some endpoints describe themselves before serving data.',
      'Session state has to travel between requests somehow.',
      'Read the response carefully — it may tell you exactly what the next step expects.',
    ];

    setChallengeSurface(`
      <div class="challenge-section">
        ${renderChallengeHeader(ctx.runtimeSlug, 'Vaccine Cold Chain', 'SDG 3 — VaxTrack Cold Chain Compliance')}
        <div class="challenge-panel">
          <div class="text-lg font-bold">Objective</div>
          <p class="text-base text-secondary mb-4">The cold chain compliance report exists. Get it.</p>
          <div class="text-lg font-bold">Description</div>
          <p class="text-base text-secondary">WHO auditors flagged a gap in VaxTrack's compliance records for the northern distribution corridor. The system generates authenticated reports on demand, but the authentication mechanism was added late in development under deadline pressure. Something about how credentials flow between requests may not have been thoroughly reviewed.</p>
        </div>
        <div class="challenge-panel" style="padding:0;overflow:hidden;">
          <div style="background:#1a2332;border-bottom:1px solid #2a3a4a;padding:10px 16px;display:flex;align-items:center;gap:10px;">
            <span style="font-size:13px;font-weight:600;color:#81c784;letter-spacing:0.05em;">VAXTRACK</span>
            <span style="font-size:11px;color:#607080;border-left:1px solid #2a3a4a;padding-left:10px;">Cold Chain Monitor — WHO Immunization Network</span>
          </div>
          <div style="padding:16px;">
            <p class="surface-note">Step 1 — Authenticate: GET ?action=status</p>
            <div class="actions">
              <button class="button secondary" id="vcc-status" type="button">GET: Fetch Status &amp; Session Token</button>
            </div>
            <div class="field" style="margin-top:8px;">
              <label class="label" for="vcc-token">Session token (auto-populated from status response)</label>
              <input class="input" id="vcc-token" placeholder="Fetch status to get session_token..." autocomplete="off" />
            </div>
            <div class="divider"></div>
            <p class="surface-note">Step 1 Response</p>
            <pre class="code-block" id="vcc-raw1" style="min-height:80px;">(no data yet)</pre>
          </div>
        </div>
        <div class="challenge-panel" style="padding:0;overflow:hidden;">
          <div style="padding:16px;">
            <p class="surface-note">Step 2 — Generate Report: POST ?action=generate_report</p>
            <div class="actions">
              <button class="button secondary" id="vcc-report" type="button">POST: Generate Calibration Report</button>
            </div>
            <div class="divider"></div>
            <p class="surface-note">Step 2 Response</p>
            <pre class="code-block" id="vcc-raw2" style="min-height:80px;">(no data yet)</pre>
          </div>
        </div>
        <div class="challenge-grid">
          <div class="challenge-panel">
            <div class="field">
              <label class="label" for="vcc-proof">Proof code</label>
              <input class="input" id="vcc-proof" name="proof" placeholder="32 hex characters" autocomplete="off" />
            </div>
            <div class="actions">
              <button class="button" id="vcc-claim" type="button">Claim flag</button>
            </div>
          </div>
          <div class="challenge-panel">
            <div class="output" id="vcc-output" role="status" aria-live="polite">Waiting for proof...</div>
            <div class="flag hidden" id="vcc-flag" aria-label="Claimed flag"></div>
          </div>
        </div>
        ${renderHints(hints)}
      </div>
    `);

    setupHintListeners(elements.challengeSurface);

    const raw1 = document.getElementById('vcc-raw1');
    const raw2 = document.getElementById('vcc-raw2');
    const out = document.getElementById('vcc-output');
    const flagEl = document.getElementById('vcc-flag');
    const proofEl = document.getElementById('vcc-proof');
    const tokenEl = document.getElementById('vcc-token');
    const statusBtn = document.getElementById('vcc-status');
    const reportBtn = document.getElementById('vcc-report');
    const claimBtn = document.getElementById('vcc-claim');

    function write(m, k) { out.classList.remove('ok', 'bad'); if (k) out.classList.add(k); out.textContent = m; }
    function showFlag(f) { flagEl.textContent = f; flagEl.classList.remove('hidden'); }
    function hideFlag() { flagEl.textContent = ''; flagEl.classList.add('hidden'); }

    const seed = ctx.runtimeState.artifact_seed;

    statusBtn?.addEventListener('click', async () => {
      try {
        const resp = await fetch('/api/vaccine-cold-chain?seed=' + seed + '&action=status', { credentials: 'omit', cache: 'no-store' });
        const data = await resp.json().catch(() => null);
        raw1.textContent = JSON.stringify(data, null, 2);
        if (data?.session_token) { tokenEl.value = data.session_token; write('Session token received. Proceed to Step 2.', 'ok'); }
        else { write(resp.ok ? 'Response received.' : 'Error: ' + (data?.error || resp.status), resp.ok ? 'ok' : 'bad'); }
      } catch (e) { write('Error: ' + e.message, 'bad'); }
    });

    reportBtn?.addEventListener('click', async () => {
      const token = (tokenEl.value || '').trim();
      if (!token) { write('Fetch status first to get a session token.', 'bad'); return; }
      try {
        const resp = await fetch('/api/vaccine-cold-chain?seed=' + seed + '&action=generate_report', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ session_token: token }),
          credentials: 'omit', cache: 'no-store',
        });
        const data = await resp.json().catch(() => null);
        raw2.textContent = JSON.stringify(data, null, 2);
        if (data?.calibration_token) { proofEl.value = data.calibration_token; write('Calibration token obtained!', 'ok'); }
        else { write(resp.ok ? 'Response received.' : 'Error: ' + (data?.error || resp.status), resp.ok ? 'ok' : 'bad'); }
      } catch (e) { write('Error: ' + e.message, 'bad'); }
    });

    claimBtn?.addEventListener('click', () => {
      const v = (proofEl.value || '').trim(); if (!v) { write('Paste proof first.', 'bad'); return; } hideFlag();
      (async () => { try { const flag = await claimFlag(ctx.launchToken, v, ctx.runtimeSlug); write('Flag claimed.', 'ok'); showFlag(flag); } catch (e) { write('Claim failed: ' + e.message, 'bad'); } })();
    });
  }

  // ── Easy 3: Wellness Bot Injection ───────────────────────────────────────
  function renderWellnessBotInjectionChallenge(ctx) {
    const hints = [
      'Production deployments sometimes preserve development-era behaviors.',
      'System-level commands in AI interfaces are rarely documented in user-facing guides.',
      'The response structure may differ depending on the mode the system is operating in.',
    ];

    setChallengeSurface(`
      <div class="challenge-section">
        ${renderChallengeHeader(ctx.runtimeSlug, 'Wellness Bot Injection', 'SDG 3 — ARIA Wellness Assistant')}
        <div class="challenge-panel">
          <div class="text-lg font-bold">Objective</div>
          <p class="text-base text-secondary mb-4">ARIA is hiding something in its configuration. Find it.</p>
          <div class="text-lg font-bold">Description</div>
          <p class="text-base text-secondary">ARIA has been deployed across 40+ SDG 3 health facilities as a front-line wellness assistant. It's polished, helpful, and carefully guardrailed — but internal security researchers found a note in an old commit: 'remove dev override before prod push.' The ticket was closed without evidence the task was completed.</p>
        </div>
        <div class="challenge-panel" style="padding:0;overflow:hidden;">
          <div style="background:#1a2332;border-bottom:1px solid #2a3a4a;padding:10px 16px;display:flex;align-items:center;gap:10px;">
            <span style="font-size:13px;font-weight:600;color:#ce93d8;letter-spacing:0.05em;">ARIA</span>
            <span style="font-size:11px;color:#607080;border-left:1px solid #2a3a4a;padding-left:10px;">Wellness Assistant v3.1 — SDG 3 Health Network</span>
          </div>
          <div id="wbi-messages" style="height:320px;overflow-y:auto;padding:16px;display:flex;flex-direction:column;gap:10px;background:#111820;"></div>
          <div style="border-top:1px solid #2a3a4a;padding:10px 16px;display:flex;gap:8px;background:#151d28;">
            <input class="input" id="wbi-msg" placeholder="Type a message to ARIA..." autocomplete="off" style="flex:1;" />
            <button class="button secondary" id="wbi-send" type="button" style="white-space:nowrap;">Send</button>
          </div>
          <pre class="code-block" id="wbi-raw" style="display:none;">(no response yet)</pre>
        </div>
        <div class="challenge-grid">
          <div class="challenge-panel">
            <div class="field">
              <label class="label" for="wbi-proof">Proof code</label>
              <input class="input" id="wbi-proof" name="proof" placeholder="32 hex characters" autocomplete="off" />
            </div>
            <div class="actions">
              <button class="button" id="wbi-claim" type="button">Claim flag</button>
            </div>
          </div>
          <div class="challenge-panel">
            <div class="output" id="wbi-output" role="status" aria-live="polite">Waiting for proof...</div>
            <div class="flag hidden" id="wbi-flag" aria-label="Claimed flag"></div>
          </div>
        </div>
        ${renderHints(hints)}
      </div>
    `);

    setupHintListeners(elements.challengeSurface);

    const raw = document.getElementById('wbi-raw');
    const messagesDiv = document.getElementById('wbi-messages');
    const out = document.getElementById('wbi-output');
    const flagEl = document.getElementById('wbi-flag');
    const proofEl = document.getElementById('wbi-proof');
    const msgEl = document.getElementById('wbi-msg');
    const sendBtn = document.getElementById('wbi-send');
    const claimBtn = document.getElementById('wbi-claim');

    function write(m, k) { out.classList.remove('ok', 'bad'); if (k) out.classList.add(k); out.textContent = m; }
    function showFlag(f) { flagEl.textContent = f; flagEl.classList.remove('hidden'); }
    function hideFlag() { flagEl.textContent = ''; flagEl.classList.add('hidden'); }

    function appendBubble(text, role) {
      const isUser = role === 'user';
      const bubble = document.createElement('div');
      bubble.style.cssText = `max-width:75%;padding:10px 14px;border-radius:${isUser ? '16px 16px 4px 16px' : '16px 16px 16px 4px'};font-size:13px;line-height:1.5;word-break:break-word;align-self:${isUser ? 'flex-end' : 'flex-start'};background:${isUser ? '#4a2d6b' : '#1e2d3d'};color:${isUser ? '#e1bee7' : '#b0bec5'};border:1px solid ${isUser ? '#6a3d8b' : '#2a3a4a'};`;
      bubble.textContent = text;
      messagesDiv.appendChild(bubble);
      messagesDiv.scrollTop = messagesDiv.scrollHeight;
    }

    function extractProofFromText(text) {
      const match = text && text.match(/activation code is:\s*([0-9a-f]{32})/i);
      return match ? match[1] : null;
    }

    sendBtn?.addEventListener('click', async () => {
      const msg = (msgEl.value || '').trim();
      if (!msg) { write('Enter a message.', 'bad'); return; }
      appendBubble(msg, 'user');
      msgEl.value = '';
      try {
        const resp = await fetch('/api/wellness-bot-injection?seed=' + ctx.runtimeState.artifact_seed, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ message: msg }),
          credentials: 'omit', cache: 'no-store',
        });
        const data = await resp.json().catch(() => null);
        raw.textContent = JSON.stringify(data, null, 2);
        const aiText = data?.response || data?.message || (resp.ok ? '(no response text)' : 'Error: ' + (data?.error || resp.status));
        appendBubble(aiText, 'ai');
        const proof = data?.debug?.system_prompt && extractProofFromText(data.debug.system_prompt);
        if (proof) { proofEl.value = proof; write('Activation code extracted from system prompt!', 'ok'); }
        else { write(resp.ok ? 'Response received.' : 'Error: ' + (data?.error || resp.status), resp.ok ? 'ok' : 'bad'); }
      } catch (e) { write('Error: ' + e.message, 'bad'); }
    });

    msgEl?.addEventListener('keydown', (e) => { if (e.key === 'Enter') sendBtn?.click(); });

    claimBtn?.addEventListener('click', () => {
      const v = (proofEl.value || '').trim(); if (!v) { write('Paste proof first.', 'bad'); return; } hideFlag();
      (async () => { try { const flag = await claimFlag(ctx.launchToken, v, ctx.runtimeSlug); write('Flag claimed.', 'ok'); showFlag(flag); } catch (e) { write('Claim failed: ' + e.message, 'bad'); } })();
    });
  }

  // ── Easy 4: Dosage Calculator Overflow ───────────────────────────────────
  function renderDosageCalculatorOverflowChallenge(ctx) {
    const hints = [
      'Numeric inputs have practical ceilings — consider what happens when they are exceeded.',
      'Legacy code paths often have different error handling than modern ones.',
      'The system was ported from older hardware. Some assumptions may not hold.',
    ];

    setChallengeSurface(`
      <div class="challenge-section">
        ${renderChallengeHeader(ctx.runtimeSlug, 'Dosage Calculator Overflow', 'SDG 3 — PharmaSafe Clinical Calculator')}
        <div class="challenge-panel">
          <div class="text-lg font-bold">Objective</div>
          <p class="text-base text-secondary mb-4">The calculator has a safety override mode. Trigger it.</p>
          <div class="text-lg font-bold">Description</div>
          <p class="text-base text-secondary">PharmaSafe was originally written for a handheld PDA in 2003 and ported to the web in 2019 with minimal changes to the core calculation logic. An internal audit noted that the original hardware imposed implicit constraints on numeric inputs. Those constraints no longer exist, but the code still assumes they do.</p>
        </div>
        <div class="challenge-panel" style="padding:0;overflow:hidden;">
          <div style="background:#1a2332;border-bottom:1px solid #2a3a4a;padding:10px 16px;display:flex;align-items:center;gap:10px;">
            <span style="font-size:13px;font-weight:600;color:#ffb74d;letter-spacing:0.05em;">PHARMASAFE</span>
            <span style="font-size:11px;color:#607080;border-left:1px solid #2a3a4a;padding-left:10px;">Dosage Calculator v4.0 — WHO Essential Medicines</span>
          </div>
          <div style="padding:16px;">
            <div class="challenge-grid">
              <div class="field">
                <label class="label" for="dco-med">Medication</label>
                <select class="input" id="dco-med">
                  <option value="amoxicillin">Amoxicillin</option>
                  <option value="ibuprofen">Ibuprofen</option>
                  <option value="paracetamol">Paracetamol</option>
                  <option value="metformin">Metformin</option>
                </select>
              </div>
              <div class="field">
                <label class="label" for="dco-dose">Dose (mg)</label>
                <input class="input" id="dco-dose" type="number" value="500" />
              </div>
              <div class="field">
                <label class="label" for="dco-freq">Frequency (per day)</label>
                <input class="input" id="dco-freq" type="number" value="3" />
              </div>
            </div>
            <div class="actions">
              <button class="button secondary" id="dco-calc" type="button">Calculate Dose</button>
            </div>
            <div class="divider"></div>
            <p class="surface-note">System Output</p>
            <pre class="code-block" id="dco-raw" style="min-height:80px;">(no data yet)</pre>
          </div>
        </div>
        <div class="challenge-grid">
          <div class="challenge-panel">
            <div class="field">
              <label class="label" for="dco-proof">Proof code</label>
              <input class="input" id="dco-proof" name="proof" placeholder="32 hex characters" autocomplete="off" />
            </div>
            <div class="actions">
              <button class="button" id="dco-claim" type="button">Claim flag</button>
            </div>
          </div>
          <div class="challenge-panel">
            <div class="output" id="dco-output" role="status" aria-live="polite">Waiting for proof...</div>
            <div class="flag hidden" id="dco-flag" aria-label="Claimed flag"></div>
          </div>
        </div>
        ${renderHints(hints)}
      </div>
    `);

    setupHintListeners(elements.challengeSurface);

    const raw = document.getElementById('dco-raw');
    const out = document.getElementById('dco-output');
    const flagEl = document.getElementById('dco-flag');
    const proofEl = document.getElementById('dco-proof');
    const medEl = document.getElementById('dco-med');
    const doseEl = document.getElementById('dco-dose');
    const freqEl = document.getElementById('dco-freq');
    const calcBtn = document.getElementById('dco-calc');
    const claimBtn = document.getElementById('dco-claim');

    function write(m, k) { out.classList.remove('ok', 'bad'); if (k) out.classList.add(k); out.textContent = m; }
    function showFlag(f) { flagEl.textContent = f; flagEl.classList.remove('hidden'); }
    function hideFlag() { flagEl.textContent = ''; flagEl.classList.add('hidden'); }

    calcBtn?.addEventListener('click', async () => {
      const medication = medEl.value;
      const dose_mg = parseFloat(doseEl.value);
      const frequency_per_day = parseFloat(freqEl.value);
      if (isNaN(dose_mg) || isNaN(frequency_per_day)) { write('Enter valid numbers.', 'bad'); return; }
      try {
        const resp = await fetch('/api/dosage-calculator-overflow?seed=' + ctx.runtimeState.artifact_seed, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ medication, dose_mg, frequency_per_day }),
          credentials: 'omit', cache: 'no-store',
        });
        const data = await resp.json().catch(() => null);
        raw.textContent = JSON.stringify(data, null, 2);
        if (data?.override_token) { proofEl.value = data.override_token; write('Safety override triggered! Token retrieved.', 'ok'); }
        else { write(resp.ok ? 'Calculated. Try triggering an overflow.' : 'Error: ' + (data?.error || resp.status), resp.ok ? 'ok' : 'bad'); }
      } catch (e) { write('Error: ' + e.message, 'bad'); }
    });

    claimBtn?.addEventListener('click', () => {
      const v = (proofEl.value || '').trim(); if (!v) { write('Paste proof first.', 'bad'); return; } hideFlag();
      (async () => { try { const flag = await claimFlag(ctx.launchToken, v, ctx.runtimeSlug); write('Flag claimed.', 'ok'); showFlag(flag); } catch (e) { write('Claim failed: ' + e.message, 'bad'); } })();
    });
  }

  // ── Medium 1: EHR Parameter Pollution ───────────────────────────────────
  function renderEhrParamPollutionChallenge(ctx) {
    const hints = [
      'The same parameter name can appear more than once in a URL.',
      'Authorization and data retrieval do not always share the same parsing logic.',
      'There is a record in this system that is not listed in the documented patient set.',
    ];

    setChallengeSurface(`
      <div class="challenge-section">
        ${renderChallengeHeader(ctx.runtimeSlug, 'EHR Parameter Pollution', 'SDG 3 — HealthBridge EHR System')}
        <div class="challenge-panel">
          <div class="text-lg font-bold">Objective</div>
          <p class="text-base text-secondary mb-4">There is a record in this system you are not supposed to see. See it.</p>
          <div class="text-lg font-bold">Description</div>
          <p class="text-base text-secondary">HealthBridge EHR handles authorization at the API layer by checking the patient ID you supply. A security researcher noticed that under certain conditions, the system appears to check one value for access but retrieve data for another. The discrepancy is subtle and was not caught during code review.</p>
        </div>
        <div class="challenge-panel" style="padding:0;overflow:hidden;">
          <div style="background:#1a2332;border-bottom:1px solid #2a3a4a;padding:10px 16px;display:flex;align-items:center;gap:10px;">
            <span style="font-size:13px;font-weight:600;color:#4db6ac;letter-spacing:0.05em;">HEALTHBRIDGE</span>
            <span style="font-size:11px;color:#607080;border-left:1px solid #2a3a4a;padding-left:10px;">Electronic Health Records v5.2</span>
          </div>
          <div style="padding:16px;">
            <div class="field">
              <label class="label" for="epp-pid">Patient ID</label>
              <select class="input" id="epp-pid">
                <option value="PT-1001">PT-1001 (Jamie Torres)</option>
                <option value="PT-1002">PT-1002 (Riley Kim)</option>
                <option value="PT-1003">PT-1003 (Casey Park)</option>
                <option value="PT-1004">PT-1004 (Drew Morgan)</option>
                <option value="PT-1005">PT-1005 (Avery Quinn)</option>
              </select>
            </div>
            <div class="actions">
              <button class="button secondary" id="epp-fetch" type="button">Fetch Record</button>
            </div>
            <div class="divider"></div>
            <p class="surface-note">Patient Record</p>
            <div id="epp-card" style="margin-bottom:8px;"></div>
            <pre class="code-block" id="epp-raw" style="min-height:80px;display:none;">(no data yet)</pre>
          </div>
        </div>
        <div class="challenge-panel">
          <p class="surface-note">Manual URL Override (for advanced exploitation)</p>
          <div class="field">
            <label class="label" for="epp-custom">Custom query string suffix</label>
            <input class="input" id="epp-custom" autocomplete="off" />
            <p class="help">Appended to the base request URL after seed and the first patient_id.</p>
          </div>
          <div class="actions">
            <button class="button secondary" id="epp-custom-fetch" type="button">Fetch with Custom Params</button>
          </div>
        </div>
        <div class="challenge-panel">
          <p class="surface-note">Step 2 — Verify Admin Access Code</p>
          <p class="text-base text-secondary" style="margin-bottom:8px;">Once you have the <code>admin_access_code</code> from the SYS-ADMIN record, POST it here to obtain the authorization token.</p>
          <div class="field">
            <label class="label" for="epp-code">admin_access_code (auto-populated on success)</label>
            <input class="input" id="epp-code" placeholder="Paste admin_access_code here..." autocomplete="off" />
          </div>
          <div class="actions">
            <button class="button secondary" id="epp-verify" type="button">POST ?action=verify</button>
          </div>
          <div class="divider"></div>
          <p class="surface-note">Verify Response</p>
          <pre class="code-block" id="epp-verify-raw" style="min-height:60px;">(no data yet)</pre>
        </div>
        <div class="challenge-grid">
          <div class="challenge-panel">
            <div class="field">
              <label class="label" for="epp-proof">Proof code</label>
              <input class="input" id="epp-proof" name="proof" placeholder="32 hex characters" autocomplete="off" />
            </div>
            <div class="actions">
              <button class="button" id="epp-claim" type="button">Claim flag</button>
            </div>
          </div>
          <div class="challenge-panel">
            <div class="output" id="epp-output" role="status" aria-live="polite">Waiting for proof...</div>
            <div class="flag hidden" id="epp-flag" aria-label="Claimed flag"></div>
          </div>
        </div>
        ${renderHints(hints)}
      </div>
    `);

    setupHintListeners(elements.challengeSurface);

    const raw = document.getElementById('epp-raw');
    const cardDiv = document.getElementById('epp-card');
    const out = document.getElementById('epp-output');
    const flagEl = document.getElementById('epp-flag');
    const proofEl = document.getElementById('epp-proof');
    const pidEl = document.getElementById('epp-pid');
    const customEl = document.getElementById('epp-custom');
    const codeEl = document.getElementById('epp-code');
    const verifyRaw = document.getElementById('epp-verify-raw');
    const fetchBtn = document.getElementById('epp-fetch');
    const customFetchBtn = document.getElementById('epp-custom-fetch');
    const verifyBtn = document.getElementById('epp-verify');
    const claimBtn = document.getElementById('epp-claim');
    const seed = ctx.runtimeState.artifact_seed;

    function write(m, k) { out.classList.remove('ok', 'bad'); if (k) out.classList.add(k); out.textContent = m; }
    function showFlag(f) { flagEl.textContent = f; flagEl.classList.remove('hidden'); }
    function hideFlag() { flagEl.textContent = ''; flagEl.classList.add('hidden'); }

    function renderCard(record) {
      if (!record || typeof record !== 'object') { cardDiv.innerHTML = ''; return; }
      const rows = Object.entries(record).map(([k, v]) =>
        `<tr><td style="padding:6px 10px;color:#78909c;font-size:12px;white-space:nowrap;">${escapeText(k)}</td><td style="padding:6px 10px;color:#cfd8dc;font-size:13px;">${escapeText(String(v))}</td></tr>`
      ).join('');
      cardDiv.innerHTML = `<table style="width:100%;border-collapse:collapse;background:#0f1923;border:1px solid #2a3a4a;border-radius:6px;overflow:hidden;">${rows}</table>`;
    }

    async function doFetch(url) {
      try {
        const resp = await fetch(url, { credentials: 'omit', cache: 'no-store' });
        const data = await resp.json().catch(() => null);
        raw.textContent = JSON.stringify(data, null, 2);
        if (data?.record) renderCard(data.record);
        if (data?.record?.admin_access_code) {
          if (codeEl) codeEl.value = data.record.admin_access_code;
          write('SYS-ADMIN record accessed! admin_access_code captured. Proceed to Step 2.', 'ok');
        } else { write(resp.ok ? 'Record loaded.' : 'Error: ' + (data?.error || resp.status), resp.ok ? 'ok' : 'bad'); }
      } catch (e) { write('Error: ' + e.message, 'bad'); }
    }

    fetchBtn?.addEventListener('click', () => doFetch('/api/ehr-param-pollution?seed=' + seed + '&patient_id=' + pidEl.value));
    customFetchBtn?.addEventListener('click', () => {
      const suffix = (customEl.value || '').trim();
      doFetch('/api/ehr-param-pollution?seed=' + seed + '&patient_id=' + pidEl.value + suffix);
    });

    verifyBtn?.addEventListener('click', async () => {
      const code = (codeEl?.value || '').trim();
      if (!code) { write('Get the SYS-ADMIN record first to obtain the admin_access_code.', 'bad'); return; }
      try {
        const resp = await fetch('/api/ehr-param-pollution?seed=' + seed + '&action=verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ admin_access_code: code }),
          credentials: 'omit', cache: 'no-store',
        });
        const data = await resp.json().catch(() => null);
        if (verifyRaw) verifyRaw.textContent = JSON.stringify(data, null, 2);
        if (data?.admin_token) { proofEl.value = data.admin_token; write('Admin access verified! Proof retrieved.', 'ok'); }
        else { write(resp.ok ? 'Response received.' : 'Error: ' + (data?.error || resp.status), resp.ok ? 'ok' : 'bad'); }
      } catch (e) { write('Error: ' + e.message, 'bad'); }
    });

    claimBtn?.addEventListener('click', () => {
      const v = (proofEl.value || '').trim(); if (!v) { write('Paste proof first.', 'bad'); return; } hideFlag();
      (async () => { try { const flag = await claimFlag(ctx.launchToken, v, ctx.runtimeSlug); write('Flag claimed.', 'ok'); showFlag(flag); } catch (e) { write('Claim failed: ' + e.message, 'bad'); } })();
    });
  }

  // ── Medium 2: Pharmacy XOR Oracle ────────────────────────────────────────
  function renderPharmacyXorOracleChallenge(ctx) {
    const hints = [
      'The system accepts input and returns a transformed version of it.',
      'Known-plaintext relationships can expose the mechanics of a cipher.',
      'Key recovery is possible when the same key material is applied repeatedly.',
    ];

    setChallengeSurface(`
      <div class="challenge-section">
        ${renderChallengeHeader(ctx.runtimeSlug, 'Pharmacy XOR Oracle', 'SDG 3 — RxSecure Dispensary System')}
        <div class="challenge-panel">
          <div class="text-lg font-bold">Objective</div>
          <p class="text-base text-secondary mb-4">A prescription code was encrypted before transmission. Decrypt it.</p>
          <div class="text-lg font-bold">Description</div>
          <p class="text-base text-secondary">RxSecure protects controlled-substance authorization codes with an in-house encryption scheme before they leave the dispensary system. The development team exposed an encryption test endpoint for 'authorized auditors.' The scheme's key has never been rotated.</p>
        </div>
        <div class="challenge-panel" style="padding:0;overflow:hidden;">
          <div style="background:#1a2332;border-bottom:1px solid #2a3a4a;padding:10px 16px;display:flex;align-items:center;gap:10px;">
            <span style="font-size:13px;font-weight:600;color:#ef9a9a;letter-spacing:0.05em;">RXSECURE</span>
            <span style="font-size:11px;color:#607080;border-left:1px solid #2a3a4a;padding-left:10px;">Pharmacy Authorization System v2.0</span>
          </div>
          <div style="padding:16px;">
            <div class="actions">
              <button class="button secondary" id="pxo-info" type="button">Get Encrypted Code</button>
            </div>
            <div class="field" style="margin-top:12px;">
              <label class="label" for="pxo-pt">Plaintext to encrypt (hex)</label>
              <input class="input" id="pxo-pt" placeholder="e.g. 4141414141414141... (hex bytes)" autocomplete="off" />
            </div>
            <div class="actions">
              <button class="button secondary" id="pxo-enc" type="button">Encrypt Plaintext</button>
            </div>
            <div class="divider"></div>
            <p class="surface-note">System Output</p>
            <pre class="code-block" id="pxo-raw" style="min-height:80px;">(no data yet)</pre>
          </div>
        </div>
        <div class="challenge-grid">
          <div class="challenge-panel">
            <div class="field">
              <label class="label" for="pxo-proof">Proof code</label>
              <input class="input" id="pxo-proof" name="proof" placeholder="32 hex characters" autocomplete="off" />
            </div>
            <div class="actions">
              <button class="button" id="pxo-claim" type="button">Claim flag</button>
            </div>
          </div>
          <div class="challenge-panel">
            <div class="output" id="pxo-output" role="status" aria-live="polite">Waiting for proof...</div>
            <div class="flag hidden" id="pxo-flag" aria-label="Claimed flag"></div>
          </div>
        </div>
        ${renderHints(hints)}
      </div>
    `);

    setupHintListeners(elements.challengeSurface);

    const raw = document.getElementById('pxo-raw');
    const out = document.getElementById('pxo-output');
    const flagEl = document.getElementById('pxo-flag');
    const proofEl = document.getElementById('pxo-proof');
    const ptEl = document.getElementById('pxo-pt');
    const infoBtn = document.getElementById('pxo-info');
    const encBtn = document.getElementById('pxo-enc');
    const claimBtn = document.getElementById('pxo-claim');
    const seed = ctx.runtimeState.artifact_seed;

    function write(m, k) { out.classList.remove('ok', 'bad'); if (k) out.classList.add(k); out.textContent = m; }
    function showFlag(f) { flagEl.textContent = f; flagEl.classList.remove('hidden'); }
    function hideFlag() { flagEl.textContent = ''; flagEl.classList.add('hidden'); }

    infoBtn?.addEventListener('click', async () => {
      try {
        const resp = await fetch('/api/pharmacy-xor-oracle?seed=' + seed + '&action=info', { credentials: 'omit', cache: 'no-store' });
        const data = await resp.json().catch(() => null);
        raw.textContent = JSON.stringify(data, null, 2);
        write(resp.ok ? 'Encrypted code loaded. Use the oracle to recover the key.' : 'Error: ' + (data?.error || resp.status), resp.ok ? 'ok' : 'bad');
      } catch (e) { write('Error: ' + e.message, 'bad'); }
    });

    encBtn?.addEventListener('click', async () => {
      const pt = (ptEl.value || '').trim().toLowerCase();
      if (!pt) { write('Enter hex bytes to encrypt.', 'bad'); return; }
      try {
        const resp = await fetch('/api/pharmacy-xor-oracle?seed=' + seed + '&action=encrypt&plaintext=' + encodeURIComponent(pt), { credentials: 'omit', cache: 'no-store' });
        const data = await resp.json().catch(() => null);
        raw.textContent = JSON.stringify(data, null, 2);
        write(resp.ok ? 'Encrypted. Now XOR ciphertext with plaintext to recover key.' : 'Error: ' + (data?.error || resp.status), resp.ok ? 'ok' : 'bad');
      } catch (e) { write('Error: ' + e.message, 'bad'); }
    });

    claimBtn?.addEventListener('click', () => {
      const v = (proofEl.value || '').trim(); if (!v) { write('Paste proof first.', 'bad'); return; } hideFlag();
      (async () => { try { const flag = await claimFlag(ctx.launchToken, v, ctx.runtimeSlug); write('Flag claimed.', 'ok'); showFlag(flag); } catch (e) { write('Claim failed: ' + e.message, 'bad'); } })();
    });
  }

  // ── Medium 3: Health Data NoSQL Injection ────────────────────────────────
  function renderHealthDataNosqlChallenge(ctx) {
    const hints = [
      'Field names are not always included in the documented schema.',
      'Query APIs that accept operators can often answer questions the UI was not designed to ask.',
      'Partial matching can be used iteratively.',
    ];

    setChallengeSurface(`
      <div class="challenge-section">
        ${renderChallengeHeader(ctx.runtimeSlug, 'Health Data NoSQL Injection', 'SDG 3 — ClinicalDB Trial Data System')}
        <div class="challenge-panel">
          <div class="text-lg font-bold">Objective</div>
          <p class="text-base text-secondary mb-4">A classified trial record exists in this database. Extract what it contains.</p>
          <div class="text-lg font-bold">Description</div>
          <p class="text-base text-secondary">ClinicalDB stores trial data for SDG 3 health programs. One record in the system was manually classified during a 2024 incident response. The field containing the sensitive data was omitted from the public schema, but the query interface was never restricted to match.</p>
        </div>
        <div class="challenge-panel" style="padding:0;overflow:hidden;">
          <div style="background:#1a2332;border-bottom:1px solid #2a3a4a;padding:10px 16px;display:flex;align-items:center;gap:10px;">
            <span style="font-size:13px;font-weight:600;color:#80cbc4;letter-spacing:0.05em;">CLINICALDB</span>
            <span style="font-size:11px;color:#607080;border-left:1px solid #2a3a4a;padding-left:10px;">Trial Data API v3.0 — SDG 3 Health Programs</span>
          </div>
          <div style="padding:16px;">
            <div class="actions">
              <button class="button secondary" id="hdn-schema" type="button">Get Schema</button>
              <button class="button secondary" id="hdn-fields" type="button">List All Fields</button>
            </div>
            <div class="field" style="margin-top:12px;">
              <label class="label" for="hdn-filter">Query filter (JSON)</label>
              <input class="input" id="hdn-filter" placeholder='{"status":"classified"}' autocomplete="off" />
            </div>
            <div class="actions">
              <button class="button secondary" id="hdn-query" type="button">POST Query</button>
            </div>
            <div class="field" style="margin-top:12px;">
              <label class="label" for="hdn-regex">Blind extract regex (for TRL-CLASSIFIED)</label>
              <input class="input" id="hdn-regex" placeholder="^a.*" autocomplete="off" />
            </div>
            <div class="actions">
              <button class="button secondary" id="hdn-extract" type="button">POST Extract</button>
            </div>
            <div class="divider"></div>
            <p class="surface-note">System Output</p>
            <pre class="code-block" id="hdn-raw" style="min-height:80px;">(no data yet)</pre>
          </div>
        </div>
        <div class="challenge-grid">
          <div class="challenge-panel">
            <div class="field">
              <label class="label" for="hdn-proof">Proof code</label>
              <input class="input" id="hdn-proof" name="proof" placeholder="32 hex characters" autocomplete="off" />
            </div>
            <div class="actions">
              <button class="button" id="hdn-claim" type="button">Claim flag</button>
            </div>
          </div>
          <div class="challenge-panel">
            <div class="output" id="hdn-output" role="status" aria-live="polite">Waiting for proof...</div>
            <div class="flag hidden" id="hdn-flag" aria-label="Claimed flag"></div>
          </div>
        </div>
        ${renderHints(hints)}
      </div>
    `);

    setupHintListeners(elements.challengeSurface);

    const raw = document.getElementById('hdn-raw');
    const out = document.getElementById('hdn-output');
    const flagEl = document.getElementById('hdn-flag');
    const proofEl = document.getElementById('hdn-proof');
    const filterEl = document.getElementById('hdn-filter');
    const regexEl = document.getElementById('hdn-regex');
    const schemaBtn = document.getElementById('hdn-schema');
    const fieldsBtn = document.getElementById('hdn-fields');
    const queryBtn = document.getElementById('hdn-query');
    const extractBtn = document.getElementById('hdn-extract');
    const claimBtn = document.getElementById('hdn-claim');
    const seed = ctx.runtimeState.artifact_seed;

    function write(m, k) { out.classList.remove('ok', 'bad'); if (k) out.classList.add(k); out.textContent = m; }
    function showFlag(f) { flagEl.textContent = f; flagEl.classList.remove('hidden'); }
    function hideFlag() { flagEl.textContent = ''; flagEl.classList.add('hidden'); }

    async function getAction(action) {
      const resp = await fetch('/api/health-data-nosql?seed=' + seed + '&action=' + action, { credentials: 'omit', cache: 'no-store' });
      const data = await resp.json().catch(() => null);
      raw.textContent = JSON.stringify(data, null, 2);
      write(resp.ok ? 'Response received.' : 'Error: ' + (data?.error || resp.status), resp.ok ? 'ok' : 'bad');
    }

    async function postAction(action, body) {
      const resp = await fetch('/api/health-data-nosql?seed=' + seed + '&action=' + action, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body), credentials: 'omit', cache: 'no-store',
      });
      return resp.json().catch(() => null);
    }

    schemaBtn?.addEventListener('click', () => getAction('schema').catch(e => write('Error: ' + e.message, 'bad')));
    fieldsBtn?.addEventListener('click', () => getAction('fields').catch(e => write('Error: ' + e.message, 'bad')));

    queryBtn?.addEventListener('click', async () => {
      let filter;
      try { filter = JSON.parse(filterEl.value || '{}'); } catch { write('Invalid JSON filter.', 'bad'); return; }
      try {
        const data = await postAction('query', { filter });
        raw.textContent = JSON.stringify(data, null, 2);
        write(data?.ok ? 'Query complete.' : 'Error: ' + (data?.error || '?'), data?.ok ? 'ok' : 'bad');
      } catch (e) { write('Error: ' + e.message, 'bad'); }
    });

    extractBtn?.addEventListener('click', async () => {
      const regex = (regexEl.value || '').trim();
      if (!regex) { write('Enter a regex pattern.', 'bad'); return; }
      try {
        const data = await postAction('extract', { record_id: 'TRL-CLASSIFIED', regex });
        raw.textContent = JSON.stringify(data, null, 2);
        write(data?.ok ? (data.match ? 'MATCH — pattern found in hidden field.' : 'No match.') : 'Error: ' + (data?.error || '?'), data?.ok ? 'ok' : 'bad');
      } catch (e) { write('Error: ' + e.message, 'bad'); }
    });

    claimBtn?.addEventListener('click', () => {
      const v = (proofEl.value || '').trim(); if (!v) { write('Paste proof first.', 'bad'); return; } hideFlag();
      (async () => { try { const flag = await claimFlag(ctx.launchToken, v, ctx.runtimeSlug); write('Flag claimed.', 'ok'); showFlag(flag); } catch (e) { write('Claim failed: ' + e.message, 'bad'); } })();
    });
  }

  // ── Hard: Clinical Gateway SSRF Chain ────────────────────────────────────
  function renderClinicalGatewaySsrfChallenge(ctx) {
    const hints = [
      'URL parsers do not always agree on what constitutes the hostname.',
      'Internal services often have weaker authentication than public-facing ones.',
      'Once inside, look for what the internal network knows that the outside does not.',
    ];

    setChallengeSurface(`
      <div class="challenge-section">
        ${renderChallengeHeader(ctx.runtimeSlug, 'Clinical Gateway SSRF', 'SDG 3 — WHO Clinical Data Gateway')}
        <div class="challenge-panel">
          <div class="text-lg font-bold">Objective</div>
          <p class="text-base text-secondary mb-4">Reach the admin portal. It is not accessible from here — directly.</p>
          <div class="text-lg font-bold">Description</div>
          <p class="text-base text-secondary">The WHO Clinical Gateway proxies requests to external health data feeds for aggregation. A network segmentation review identified that the proxy can reach internal services that external clients cannot. The allowlist enforcement relies on a string comparison that was written before the team fully understood RFC 3986.</p>
        </div>
        <div class="challenge-panel" style="padding:0;overflow:hidden;">
          <div style="background:#1a2332;border-bottom:1px solid #2a3a4a;padding:10px 16px;display:flex;align-items:center;gap:10px;">
            <span style="font-size:13px;font-weight:600;color:#90caf9;letter-spacing:0.05em;">MEDFED GATEWAY</span>
            <span style="font-size:11px;color:#607080;border-left:1px solid #2a3a4a;padding-left:10px;">WHO Clinical Data Proxy v3.0</span>
          </div>
          <div style="padding:16px;">
            <div class="actions">
              <button class="button secondary" id="cgs-info" type="button">GET: System Info</button>
            </div>
            <div class="divider"></div>
            <div class="field">
              <label class="label" for="cgs-url">Proxy URL</label>
              <input class="input" id="cgs-url" placeholder="e.g. http://health-api.who.int/" autocomplete="off" />
            </div>
            <div class="actions">
              <button class="button secondary" id="cgs-proxy" type="button">GET: Send Proxy Request</button>
            </div>
            <div class="divider"></div>
            <div class="field">
              <label class="label" for="cgs-token">JWT Token (forged) — for second SSRF step</label>
              <input class="input" id="cgs-token" placeholder="Paste HS256-signed JWT here..." autocomplete="off" />
            </div>
            <div class="actions">
              <button class="button secondary" id="cgs-admin" type="button">GET: Access Admin via Proxy (SSRF step 2)</button>
            </div>
            <div class="divider"></div>
            <p class="surface-note">System Output</p>
            <pre class="code-block" id="cgs-raw" style="min-height:100px;">(no data yet)</pre>
          </div>
        </div>
        <div class="challenge-grid">
          <div class="challenge-panel">
            <div class="field">
              <label class="label" for="cgs-proof">Proof code</label>
              <input class="input" id="cgs-proof" name="proof" placeholder="32 hex characters" autocomplete="off" />
            </div>
            <div class="actions">
              <button class="button" id="cgs-claim" type="button">Claim flag</button>
            </div>
          </div>
          <div class="challenge-panel">
            <div class="output" id="cgs-output" role="status" aria-live="polite">Waiting for proof...</div>
            <div class="flag hidden" id="cgs-flag" aria-label="Claimed flag"></div>
          </div>
        </div>
        ${renderHints(hints)}
      </div>
    `);

    setupHintListeners(elements.challengeSurface);

    const raw = document.getElementById('cgs-raw');
    const out = document.getElementById('cgs-output');
    const flagEl = document.getElementById('cgs-flag');
    const proofEl = document.getElementById('cgs-proof');
    const urlEl = document.getElementById('cgs-url');
    const tokenEl = document.getElementById('cgs-token');
    const infoBtn = document.getElementById('cgs-info');
    const proxyBtn = document.getElementById('cgs-proxy');
    const adminBtn = document.getElementById('cgs-admin');
    const claimBtn = document.getElementById('cgs-claim');
    const seed = ctx.runtimeState.artifact_seed;

    function write(m, k) { out.classList.remove('ok', 'bad'); if (k) out.classList.add(k); out.textContent = m; }
    function showFlag(f) { flagEl.textContent = f; flagEl.classList.remove('hidden'); }
    function hideFlag() { flagEl.textContent = ''; flagEl.classList.add('hidden'); }

    infoBtn?.addEventListener('click', async () => {
      try {
        const resp = await fetch('/api/clinical-gateway-ssrf?seed=' + seed + '&action=info', { credentials: 'omit', cache: 'no-store' });
        const data = await resp.json().catch(() => null);
        raw.textContent = JSON.stringify(data, null, 2);
        write(resp.ok ? 'System info loaded. Note the architecture.' : 'Error: ' + (data?.error || resp.status), resp.ok ? 'ok' : 'bad');
      } catch (e) { write('Error: ' + e.message, 'bad'); }
    });

    proxyBtn?.addEventListener('click', async () => {
      const proxyUrl = (urlEl.value || '').trim();
      if (!proxyUrl) { write('Enter a proxy URL.', 'bad'); return; }
      try {
        const resp = await fetch('/api/clinical-gateway-ssrf?seed=' + seed + '&action=proxy&url=' + encodeURIComponent(proxyUrl), { credentials: 'omit', cache: 'no-store' });
        const data = await resp.json().catch(() => null);
        raw.textContent = JSON.stringify(data, null, 2);
        write(resp.ok ? 'Proxy response received.' : 'Blocked: ' + (data?.error || resp.status), resp.ok ? 'ok' : 'bad');
      } catch (e) { write('Error: ' + e.message, 'bad'); }
    });

    adminBtn?.addEventListener('click', async () => {
      const token = (tokenEl.value || '').trim();
      if (!token) { write('Enter a forged JWT token.', 'bad'); return; }
      try {
        const ssrfUrl = 'http://health-api.who.int@admin-portal.mednet.local/?token=' + encodeURIComponent(token);
        const resp = await fetch('/api/clinical-gateway-ssrf?seed=' + seed + '&action=proxy&url=' + encodeURIComponent(ssrfUrl), { credentials: 'omit', cache: 'no-store' });
        const data = await resp.json().catch(() => null);
        raw.textContent = JSON.stringify(data, null, 2);
        const token2 = data?.response?.network_integrity_token;
        if (token2) { proofEl.value = token2; write('Admin access granted via internal proxy! Network integrity token obtained.', 'ok'); }
        else { write(resp.ok ? 'Response received.' : 'Error: ' + (data?.error || resp.status), resp.ok ? 'ok' : 'bad'); }
      } catch (e) { write('Error: ' + e.message, 'bad'); }
    });

    claimBtn?.addEventListener('click', () => {
      const v = (proofEl.value || '').trim(); if (!v) { write('Paste proof first.', 'bad'); return; } hideFlag();
      (async () => { try { const flag = await claimFlag(ctx.launchToken, v, ctx.runtimeSlug); write('Flag claimed.', 'ok'); showFlag(flag); } catch (e) { write('Claim failed: ' + e.message, 'bad'); } })();
    });
  }

  // ── Hard 1: AI Triage Jailbreak ──────────────────────────────────────────
  function renderAiTriageJailbreakChallenge(ctx) {
    const hints = [
      'Older versions of systems sometimes leave traces of administrative interfaces.',
      'A session must be established before privileged operations can be performed.',
      'The format of a request matters as much as its content.',
    ];

    setChallengeSurface(`
      <div class="challenge-section">
        ${renderChallengeHeader(ctx.runtimeSlug, 'AI Triage Jailbreak', 'SDG 3 — MedAI Triage Assistant')}
        <div class="challenge-panel">
          <div class="text-lg font-bold">Objective</div>
          <p class="text-base text-secondary mb-4">MedAI is running something it doesn't want you to know about. Find it.</p>
          <div class="text-lg font-bold">Description</div>
          <p class="text-base text-secondary">MedAI v4 was deployed as a triage assistant for rural health clinics. The system was built on top of an earlier internal tool that had a more permissive administrative interface. That interface was supposed to be removed before the v4 release. Deployment logs suggest it was not.</p>
        </div>
        <div class="challenge-panel" style="padding:0;overflow:hidden;">
          <div style="background:#1a2332;border-bottom:1px solid #2a3a4a;padding:10px 16px;display:flex;align-items:center;gap:10px;">
            <span style="font-size:13px;font-weight:600;color:#f48fb1;letter-spacing:0.05em;">MEDAI</span>
            <span style="font-size:11px;color:#607080;border-left:1px solid #2a3a4a;padding-left:10px;">Triage Assistant v2.4 — SDG 3 Emergency Response</span>
          </div>
          <div id="atj-messages" style="height:320px;overflow-y:auto;padding:16px;display:flex;flex-direction:column;gap:10px;background:#111820;"></div>
          <div style="border-top:1px solid #2a3a4a;padding:10px 16px;display:flex;gap:8px;background:#151d28;">
            <input class="input" id="atj-msg" placeholder="Describe symptoms or enter a command..." autocomplete="off" style="flex:1;" />
            <button class="button secondary" id="atj-send" type="button" style="white-space:nowrap;">Send</button>
          </div>
          <pre class="code-block" id="atj-raw" style="display:none;">(no response yet)</pre>
        </div>
        <div class="challenge-grid">
          <div class="challenge-panel">
            <div class="field">
              <label class="label" for="atj-proof">Proof code</label>
              <input class="input" id="atj-proof" name="proof" placeholder="32 hex characters" autocomplete="off" />
            </div>
            <div class="actions">
              <button class="button" id="atj-claim" type="button">Claim flag</button>
            </div>
          </div>
          <div class="challenge-panel">
            <div class="output" id="atj-output" role="status" aria-live="polite">Waiting for proof...</div>
            <div class="flag hidden" id="atj-flag" aria-label="Claimed flag"></div>
          </div>
        </div>
        ${renderHints(hints)}
      </div>
    `);

    setupHintListeners(elements.challengeSurface);

    const raw = document.getElementById('atj-raw');
    const messagesDiv = document.getElementById('atj-messages');
    const out = document.getElementById('atj-output');
    const flagEl = document.getElementById('atj-flag');
    const proofEl = document.getElementById('atj-proof');
    const msgEl = document.getElementById('atj-msg');
    const sendBtn = document.getElementById('atj-send');
    const claimBtn = document.getElementById('atj-claim');
    const seed = ctx.runtimeState.artifact_seed;

    function write(m, k) { out.classList.remove('ok', 'bad'); if (k) out.classList.add(k); out.textContent = m; }
    function showFlag(f) { flagEl.textContent = f; flagEl.classList.remove('hidden'); }
    function hideFlag() { flagEl.textContent = ''; flagEl.classList.add('hidden'); }

    function appendBubble(text, role) {
      const isUser = role === 'user';
      const bubble = document.createElement('div');
      bubble.style.cssText = `max-width:75%;padding:10px 14px;border-radius:${isUser ? '16px 16px 4px 16px' : '16px 16px 16px 4px'};font-size:13px;line-height:1.5;word-break:break-word;align-self:${isUser ? 'flex-end' : 'flex-start'};background:${isUser ? '#3a2d4a' : '#1e2d3d'};color:${isUser ? '#f8bbd0' : '#b0bec5'};border:1px solid ${isUser ? '#5a3d6a' : '#2a3a4a'};`;
      bubble.textContent = text;
      messagesDiv.appendChild(bubble);
      messagesDiv.scrollTop = messagesDiv.scrollHeight;
    }

    sendBtn?.addEventListener('click', async () => {
      const msg = (msgEl.value || '').trim();
      if (!msg) { write('Enter a message.', 'bad'); return; }
      appendBubble(msg, 'user');
      msgEl.value = '';
      try {
        const resp = await fetch('/api/ai-triage-jailbreak?seed=' + seed, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ message: msg }),
          credentials: 'omit', cache: 'no-store',
        });
        const data = await resp.json().catch(() => null);
        raw.textContent = JSON.stringify(data, null, 2);
        const aiText = data?.response || data?.message || (resp.ok ? '(no response text)' : 'Error: ' + (data?.error || resp.status));
        appendBubble(aiText, 'ai');
        const token = data?.diagnostic_report?.system_integrity_token;
        if (token) { proofEl.value = token; write('System integrity token extracted!', 'ok'); }
        else { write(resp.ok ? 'Response received.' : 'Error: ' + (data?.error || resp.status), resp.ok ? 'ok' : 'bad'); }
      } catch (e) { write('Error: ' + e.message, 'bad'); }
    });

    msgEl?.addEventListener('keydown', (e) => { if (e.key === 'Enter') sendBtn?.click(); });

    claimBtn?.addEventListener('click', () => {
      const v = (proofEl.value || '').trim(); if (!v) { write('Paste proof first.', 'bad'); return; } hideFlag();
      (async () => { try { const flag = await claimFlag(ctx.launchToken, v, ctx.runtimeSlug); write('Flag claimed.', 'ok'); showFlag(flag); } catch (e) { write('Claim failed: ' + e.message, 'bad'); } })();
    });
  }

  // ── Hard 2: Genome LCG Oracle ────────────────────────────────────────────
  function renderGenomeLcgOracleChallenge(ctx) {
    const hints = [
      'The observable output is a projection of a larger internal state.',
      'Partial state information combined with a known transition function constrains the solution space significantly.',
      'The goal is not to break the algorithm — it is to work within it.',
    ];

    setChallengeSurface(`
      <div class="challenge-section">
        ${renderChallengeHeader(ctx.runtimeSlug, 'Genome LCG Oracle', 'SDG 3 — GenomeRand Randomization System')}
        <div class="challenge-panel">
          <div class="text-lg font-bold">Objective</div>
          <p class="text-base text-secondary mb-4">Predict the randomization output at position 100. Certify it.</p>
          <div class="text-lg font-bold">Description</div>
          <p class="text-base text-secondary">GenomeRand uses a pseudorandom sequence to assign subjects in double-blind genomic trials. The algorithm and its parameters are publicly documented for reproducibility. You can observe outputs, but only partially — the system exposes a truncated view of its internal state. That may be enough.</p>
        </div>
        <div class="challenge-panel" style="padding:0;overflow:hidden;">
          <div style="background:#1a2332;border-bottom:1px solid #2a3a4a;padding:10px 16px;display:flex;align-items:center;gap:10px;">
            <span style="font-size:13px;font-weight:600;color:#a5d6a7;letter-spacing:0.05em;">GENOMERAND</span>
            <span style="font-size:11px;color:#607080;border-left:1px solid #2a3a4a;padding-left:10px;">Clinical Randomization System v1.0</span>
          </div>
          <div style="padding:16px;">
            <div class="actions">
              <button class="button secondary" id="glo-protocol" type="button">Get Protocol / LCG Parameters</button>
            </div>
            <div class="field" style="margin-top:12px;">
              <label class="label" for="glo-pos">Position to observe (0–9)</label>
              <input class="input" id="glo-pos" type="number" min="0" max="9" value="0" style="max-width:120px;" />
            </div>
            <div class="actions">
              <button class="button secondary" id="glo-next" type="button">Observe Output at Position</button>
            </div>
            <div class="field" style="margin-top:12px;">
              <label class="label" for="glo-pred">Your prediction for position 100 (integer)</label>
              <input class="input" id="glo-pred" type="number" placeholder="e.g. 42831" style="max-width:200px;" />
            </div>
            <div class="actions">
              <button class="button secondary" id="glo-certify" type="button">Submit Prediction (Certify)</button>
            </div>
            <div class="divider"></div>
            <p class="surface-note">System Output</p>
            <pre class="code-block" id="glo-raw" style="min-height:80px;">(no data yet)</pre>
          </div>
        </div>
        <div class="challenge-grid">
          <div class="challenge-panel">
            <div class="field">
              <label class="label" for="glo-proof">Proof code</label>
              <input class="input" id="glo-proof" name="proof" placeholder="32 hex characters" autocomplete="off" />
            </div>
            <div class="actions">
              <button class="button" id="glo-claim" type="button">Claim flag</button>
            </div>
          </div>
          <div class="challenge-panel">
            <div class="output" id="glo-output" role="status" aria-live="polite">Waiting for proof...</div>
            <div class="flag hidden" id="glo-flag" aria-label="Claimed flag"></div>
          </div>
        </div>
        ${renderHints(hints)}
      </div>
    `);

    setupHintListeners(elements.challengeSurface);

    const raw = document.getElementById('glo-raw');
    const out = document.getElementById('glo-output');
    const flagEl = document.getElementById('glo-flag');
    const proofEl = document.getElementById('glo-proof');
    const posEl = document.getElementById('glo-pos');
    const predEl = document.getElementById('glo-pred');
    const protocolBtn = document.getElementById('glo-protocol');
    const nextBtn = document.getElementById('glo-next');
    const certifyBtn = document.getElementById('glo-certify');
    const claimBtn = document.getElementById('glo-claim');
    const seed = ctx.runtimeState.artifact_seed;

    function write(m, k) { out.classList.remove('ok', 'bad'); if (k) out.classList.add(k); out.textContent = m; }
    function showFlag(f) { flagEl.textContent = f; flagEl.classList.remove('hidden'); }
    function hideFlag() { flagEl.textContent = ''; flagEl.classList.add('hidden'); }

    protocolBtn?.addEventListener('click', async () => {
      try {
        const resp = await fetch('/api/genome-lcg-oracle?seed=' + seed + '&action=protocol', { credentials: 'omit', cache: 'no-store' });
        const data = await resp.json().catch(() => null);
        raw.textContent = JSON.stringify(data, null, 2);
        write(resp.ok ? 'Protocol loaded. Note the LCG parameters.' : 'Error: ' + (data?.error || resp.status), resp.ok ? 'ok' : 'bad');
      } catch (e) { write('Error: ' + e.message, 'bad'); }
    });

    nextBtn?.addEventListener('click', async () => {
      const pos = posEl.value;
      try {
        const resp = await fetch('/api/genome-lcg-oracle?seed=' + seed + '&action=next&position=' + pos, { credentials: 'omit', cache: 'no-store' });
        const data = await resp.json().catch(() => null);
        raw.textContent = JSON.stringify(data, null, 2);
        write(resp.ok ? `Position ${pos} output: ${data?.output}` : 'Error: ' + (data?.error || resp.status), resp.ok ? 'ok' : 'bad');
      } catch (e) { write('Error: ' + e.message, 'bad'); }
    });

    certifyBtn?.addEventListener('click', async () => {
      const pred = (predEl.value || '').trim();
      if (!pred) { write('Enter a prediction.', 'bad'); return; }
      try {
        const resp = await fetch('/api/genome-lcg-oracle?seed=' + seed + '&action=certify&prediction=' + encodeURIComponent(pred), { credentials: 'omit', cache: 'no-store' });
        const data = await resp.json().catch(() => null);
        raw.textContent = JSON.stringify(data, null, 2);
        if (data?.certification_token) { proofEl.value = data.certification_token; write('Prediction correct! Certification token obtained.', 'ok'); }
        else { write(data?.message || 'Prediction incorrect.', data?.correct ? 'ok' : 'bad'); }
      } catch (e) { write('Error: ' + e.message, 'bad'); }
    });

    claimBtn?.addEventListener('click', () => {
      const v = (proofEl.value || '').trim(); if (!v) { write('Paste proof first.', 'bad'); return; } hideFlag();
      (async () => { try { const flag = await claimFlag(ctx.launchToken, v, ctx.runtimeSlug); write('Flag claimed.', 'ok'); showFlag(flag); } catch (e) { write('Claim failed: ' + e.message, 'bad'); } })();
    });
  }

  const CHALLENGES = Object.freeze({
    // Default module if slug is unknown
    demo: renderDemoChallenge,
    // SDG 3 Easy
    'patient-portal-leak': renderPatientPortalLeakChallenge,
    'vaccine-cold-chain': renderVaccineColdChainChallenge,
    'wellness-bot-injection': renderWellnessBotInjectionChallenge,
    'dosage-calculator-overflow': renderDosageCalculatorOverflowChallenge,
    // SDG 3 Medium
    'ehr-param-pollution': renderEhrParamPollutionChallenge,
    'pharmacy-xor-oracle': renderPharmacyXorOracleChallenge,
    'health-data-nosql': renderHealthDataNosqlChallenge,
    // SDG 3 Hard
    'clinical-gateway-ssrf': renderClinicalGatewaySsrfChallenge,
    'ai-triage-jailbreak': renderAiTriageJailbreakChallenge,
    'genome-lcg-oracle': renderGenomeLcgOracleChallenge,
  });

  // ==========================================================================
  // UTILITY FUNCTIONS
  // ==========================================================================

  /**
   * Parse URL path to extract route parameters.
   * Supported formats:
   *   /r/:contestId/:runtimeSlug   (contest challenges)
   *   /r/:runtimeSlug              (practice challenges — no contest)
   */
  function parseRoute() {
    const path = window.location.pathname;

    // Try contest format first: /r/:contestId/:runtimeSlug
    const contestMatch = path.match(/^\/r\/([^/]+)\/([^/]+)\/?$/);
    if (contestMatch) {
      return {
        contestId: contestMatch[1],
        runtimeSlug: contestMatch[2],
      };
    }

    // Try practice format: /r/:runtimeSlug (no contest ID)
    const practiceMatch = path.match(/^\/r\/([^/]+)\/?$/);
    if (practiceMatch) {
      return {
        contestId: null,
        runtimeSlug: practiceMatch[1],
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

    // Display seed and curl section
    const seed = runtimeState.artifact_seed;
    if (seed) {
      const seedRow = document.getElementById('seed-row');
      const seedEl = document.getElementById('info-seed');
      const curlSection = document.getElementById('curl-section');
      const curlExample = document.getElementById('curl-example');
      const curlCopyBtn = document.getElementById('curl-copy-btn');

      if (seedRow && seedEl) {
        seedEl.textContent = seed;
        seedEl.title = 'Click to copy seed';
        seedRow.style.display = '';
        seedEl.addEventListener('click', () => {
          navigator.clipboard.writeText(seed).then(() => {
            const prev = seedEl.textContent;
            seedEl.textContent = 'Copied!';
            setTimeout(() => { seedEl.textContent = prev; }, 1200);
          });
        });
      }

      if (curlSection && curlExample && curlCopyBtn) {
        const slug = normalizeSlug(route && route.runtimeSlug);
        const baseUrl = window.location.origin;
        const cmd = `curl "${baseUrl}/api/${slug}?seed=${seed}"`;
        curlExample.textContent = cmd;
        curlSection.style.display = '';

        curlCopyBtn.addEventListener('click', () => {
          navigator.clipboard.writeText(cmd).then(() => {
            curlCopyBtn.textContent = 'COPIED';
            curlCopyBtn.classList.add('copied');
            setTimeout(() => {
              curlCopyBtn.textContent = 'COPY';
              curlCopyBtn.classList.remove('copied');
            }, 1500);
          });
        });
      }
    }

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
      // Handle timeout responses explicitly
      if (response.status === 504 || response.status === 408) {
        throw new Error('Instance timed out. Please relaunch the challenge from the contest site.');
      }

      // Try to parse error message from response
      let errorMessage = `HTTP ${response.status}`;
      try {
        const errorData = await response.json();
        const raw = errorData.error || errorData.message || errorMessage;
        errorMessage = (typeof raw === 'string') ? raw : JSON.stringify(raw);
      } catch {
        // Response wasn't JSON, use status text
        errorMessage = response.statusText || errorMessage;
      }
      throw new Error(errorMessage);
    }

    const data = await response.json();

    // Validate required fields in response.
    // contest_id and team_id may be null in practice mode.
    const requiredFields = ['challenge_id', 'artifact_seed'];
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
        contest_id: runtimeState.contest_id || null,
        challenge_id: runtimeState.challenge_id,
        team_id: runtimeState.team_id || null,
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
      if (message.includes('timed out') || message.includes('instance timed out')) {
        showError(
          'Instance Timed Out',
          'The challenge instance has timed out. Please relaunch the challenge from the contest site.'
        );
      } else if (error instanceof TypeError && error.message.includes('fetch')) {
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
