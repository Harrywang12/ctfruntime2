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

      <div class="challenge-panel" style="background: var(--color-success-bg); border: 1px solid var(--color-success); margin-bottom: 20px;">
        <p class="surface-note" style="color: var(--color-success); margin-bottom: 12px;"><strong>How to solve:</strong></p>
        <ol style="margin-left: 20px; color: var(--color-text-secondary); line-height: 1.8; font-size: 14px;">
          <li><strong>Find the proof code</strong> (32 hex characters) hidden on this challenge page.</li>
          <li><strong>Paste the proof</strong> into the form below and click "Claim flag".</li>
          <li><strong>You'll receive your flag</strong> — it will be a string like <code>SDG{...}</code>.</li>
          <li><strong>Copy and submit the flag</strong> on the main contest platform to earn points.</li>
        </ol>
      </div>

      <div class="challenge-panel" role="region" aria-label="SDG 15 poster">
        <div class="pill sdg-tag">SDG 15 • Life on Land</div>
        <div class="sdg-poster">
          <div class="sdg-poster-row">

              <h4 class="sdg-poster-title">Protect forests, protect life.</h4>
              <p class="sdg-poster-text">
                Wildlife conservation is often discussed as a distant or optional concern, but in reality it is a fundamental issue tied to the health of the planet and the future of humanity. Across the world, ecosystems are under increasing pressure, and the survival of countless species now depends on deliberate human action.<br><br>
                Wildlife is not separate from human life. Every ecosystem functions as a connected system, where plants, animals, and natural processes rely on one another to remain stable. Forests help regulate climate and air quality. Wetlands filter water and reduce flooding. Pollinators such as bees and butterflies make food production possible. When wildlife populations decline, these systems weaken, and the consequences extend far beyond the loss of individual species.<br><br>
                Over the past century, human activity has altered the natural world at an unprecedented pace. Expanding cities, industrial agriculture, deforestation, pollution, and climate change have destroyed or fragmented habitats across the globe. Many species are unable to adapt quickly enough to these changes. As a result, scientists warn that the planet is currently experiencing a mass extinction event, driven largely by human behavior rather than natural causes.<br><br>
                The loss of wildlife is not limited to rare or visually striking animals. Each species plays a role in maintaining ecological balance. When one species disappears, it can trigger a chain reaction throughout an ecosystem. Predators may lose prey, vegetation may become overgrazed, and soil and water systems may degrade. A well documented example is the removal of top predators from certain environments, which has led to overpopulation of herbivores, destruction of plant life, and long term damage to entire landscapes.<br><br>
                Despite this, wildlife conservation is sometimes framed as a barrier to economic development. This perspective assumes a tradeoff between environmental protection and human progress. In reality, the two are closely connected. Healthy ecosystems support industries such as agriculture, fishing, tourism, and forestry. Conservation efforts often reduce long term costs by preventing soil erosion, water contamination, and natural disasters. Protecting nature is not an obstacle to progress but a foundation for sustainable growth.<br><br>
                Wildlife conservation also carries ethical significance. Humans have become the dominant force shaping the planet, giving them a unique responsibility. Many species face extinction not because of natural competition, but because of habitat destruction, illegal hunting, and environmental pollution. Conservation recognizes that other forms of life have intrinsic value and that future generations deserve a world rich in biodiversity rather than one defined by loss.<br><br>
                Efforts to protect wildlife take many forms. Governments establish protected areas such as national parks and wildlife reserves. Scientists conduct research to understand population trends and ecosystem health. Conservation organizations work with local communities to promote sustainable land use. International agreements aim to limit poaching and illegal wildlife trade. While these efforts are not perfect, they demonstrate that meaningful action is possible.<br><br>
                Individual choices also play a role. Reducing waste, supporting sustainable products, conserving energy, and learning about environmental issues all contribute to broader conservation goals. When individuals and communities act with awareness, their combined impact can influence industries and policies.<br><br>
                Wildlife conservation is ultimately about preserving balance. It is about recognizing that the well being of humans is inseparable from the well being of the natural world. Protecting wildlife is not simply an act of preservation, but an investment in a stable, resilient future for the planet and all who depend on it.<br><br>
                By choosing conservation, humanity chooses responsibility, foresight, and respect for life beyond itself.
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
        const qs = new URLSearchParams({ seed: ctx.runtimeState.artifact_seed });
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
    // Easy challenge: user triggers a report download and finds the proof in
    // request/response metadata (not rendered in the DOM).
    // The real flag is claimed dynamically from the backend.

    setChallengeSurface(`
      ${renderChallengeHeader(
      ctx.runtimeSlug,
      'Save the Species',
      'A conservation status table with a report export. Find the archive tag used for the export, then claim the flag.'
    )}

      <div class="challenge-panel" style="background: var(--color-success-bg); border: 1px solid var(--color-success); margin-bottom: 20px;">
        <p class="surface-note" style="color: var(--color-success); margin-bottom: 12px;"><strong>How to solve:</strong></p>
        <ol style="margin-left: 20px; color: var(--color-text-secondary); line-height: 1.8; font-size: 14px;">
          <li><strong>Find the proof code</strong> (32 hex characters) by exploring this challenge.</li>
          <li><strong>Paste the proof</strong> into the form and click "Claim flag".</li>
          <li><strong>You'll receive your flag</strong> — it will be a string like <code>SDG{...}</code>.</li>
          <li><strong>Copy and submit the flag</strong> on the main contest platform to earn points.</li>
        </ol>
      </div>

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
            <td>Archived monitoring report available (export required).</td>
          </tr>
          <tr>
            <td>Snow leopard</td>
            <td>Vulnerable</td>
            <td>Human-wildlife conflict; shrinking range.</td>
          </tr>
        </tbody>
      </table>

      <div class="divider"></div>

      <div class="challenge-panel">
        <p class="surface-note">Field report export</p>
        <p class="help">Something interesting happens in the DevTools network section when you click download!</p>
        <div class="actions">
          <button class="button secondary" id="sts-download" type="button">Download report</button>
        </div>
        <pre class="code-block" id="sts-raw" style="white-space: pre-wrap; overflow-wrap: anywhere;">(no report yet)</pre>
      </div>

      <div class="divider"></div>

      <div class="challenge-grid">
        <div class="challenge-panel">
          <div class="field">
            <label class="label" for="sts-proof">Proof code</label>
            <input class="input" id="sts-proof" name="proof" placeholder="32 hex characters" autocomplete="off" />
            <p class="help">Paste the archive tag you found from the export request/response.</p>
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
    const downloadBtn = document.getElementById('sts-download');
    const out = document.getElementById('sts-output');
    const flagEl = document.getElementById('sts-flag');
    const rawEl = document.getElementById('sts-raw');

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

    async function downloadReport() {
      if (!ctx.launchToken) {
        write('Missing launch token; cannot download report.', 'bad');
        return;
      }

      write('Downloading report…', 'ok');
      try {
        const qs = new URLSearchParams({ seed: ctx.runtimeState.artifact_seed });
        const resp = await fetch(`/api/save-the-species?${qs.toString()}`, {
          method: 'GET',
          credentials: 'omit',
          cache: 'no-store',
        });

        // Intentionally do NOT read or display any proof-like metadata here.
        const text = await resp.text();
        if (rawEl) {
          try {
            const parsed = JSON.parse(text);
            rawEl.textContent = JSON.stringify(parsed, null, 2);
          } catch {
            rawEl.textContent = text;
          }
        }

        if (!resp.ok) {
          let msg = `HTTP ${resp.status}`;
          try {
            const parsed = JSON.parse(text);
            msg = parsed?.error || parsed?.message || msg;
          } catch {
            // ignore
          }
          write(`Report download failed: ${msg}`, 'bad');
          return;
        }

        write('Report downloaded. Check Network → response headers for the archive tag.', 'ok');
      } catch (e) {
        const msg = (e && e.message) ? e.message : 'Unknown error';
        write(`Report download failed: ${msg}`, 'bad');
      }
    }

    downloadBtn?.addEventListener('click', downloadReport);
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

      <div class="challenge-panel" style="background: var(--color-accent-glow); border: 1px solid var(--color-accent); margin-bottom: 18px;">
        <strong>Description:</strong> Your goal is to obtain the telemetry proof code that is normally restricted by the UI. Bypass the client-side gate and retrieve the code to claim your flag.
      </div>

      <div class="challenge-panel">
        <p class="help">Public brief:</p>
        <p class="sdg-poster-text">We monitor key habitats, track illegal logging signals, and publish open data.</p>
        <p class="sdg-poster-text">Certain telemetry is <strong>restricted</strong>, but this gate is only enforced client-side.</p>
      </div>

      <div class="challenge-panel" id="ea-guard">
        <div id="ea-locked" class="${hasBypassParam ? 'hidden' : ''}">
          <p class="surface-note">Restricted telemetry requires reviewer approval.</p>
          <p class="help">Hint: The restriction is enforced only in the browser. Try manipulating the UI or URL, or use DevTools to change variables and see if you can access the telemetry.</p>
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
        const qs = new URLSearchParams({ seed: ctx.runtimeState.artifact_seed, slug: ctx.runtimeSlug });
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

      <div class="challenge-panel" style="background: var(--color-accent-glow); border: 1px solid var(--color-accent); margin-bottom: 18px;">
        <strong>Description:</strong> Your goal is to find a verification token that will pass the check and allow you to claim the flag. The token format is <code>VER-&lt;permitId&gt;-&lt;signature&gt;</code>, where the signature is derived from the permitId.
      </div>

      <div class="challenge-panel">
        <p class="surface-note" style="font-size: 13px; opacity: 0.8;">Compliance Officer View</p>
        <p style="font-size: 13px; line-height: 1.6; color: var(--color-text-secondary);">
          Permit uploads and satellite pings are "verified" by a weak token check. No real secrets here.
        </p>
        <ul style="margin-left: 16px; list-style: disc; font-size: 13px; line-height: 1.6; color: var(--color-text-secondary);">
          <li>Enter any token starting with <code>VER-</code></li>
          <li>Some systems are more trusting than they should be. Not all checks are as thorough as they seem.</li>
        </ul>
      </div>

      <div class="challenge-panel" style="background: var(--color-success-bg); border: 1px solid var(--color-success); margin-bottom: 18px;">
        <p style="color: var(--color-success); margin-bottom: 8px; font-weight: 600;">💡 Hints:</p>
        <ol style="margin-left: 20px; color: var(--color-text-secondary); line-height: 1.8; font-size: 14px;">
          <li><strong>Token Format:</strong> The token is <code>VER-&lt;permitId&gt;-&lt;signature&gt;</code>. Example: <code>VER-forest2026-a1b2c3d4</code></li>
          <li><strong>How signatures work:</strong> The signature should be derived by hashing the permitId. A common hash algorithm is SHA-256.</li>
          <li><strong>Verification flaw:</strong> Open your browser's DevTools (F12) and look at the JavaScript code that validates tokens. Does it check the <em>entire</em> signature, or just part of it?</li>
          <li><strong>Exploit:</strong> If only a small part of the signature is checked, you might be able to brute-force or craft a valid token.</li>
        </ol>
      </div>

      <div class="challenge-grid">
        <div class="challenge-panel">
          <div class="field">
            <label class="label" for="iln-token">Verification token</label>
            <input class="input" id="iln-token" name="token" autocomplete="off" />
            <p class="help">Hint: Check the client-side JavaScript validation code in your DevTools. Look for how many characters of the signature are actually verified.</p>
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

        const seed = ctx?.runtimeState?.artifact_seed;
        if (!seed || !/^[0-9a-f]{64}$/i.test(String(seed))) {
          write('Missing or invalid runtime seed; cannot request proof.', 'bad');
          return;
        }

        write('Verification passed. Requesting proof…', 'ok');

        try {
          // IMPORTANT: use `seed` here instead of `token`.
          // The launch token is one-time and is already redeemed during runtime init.
          const qs = new URLSearchParams({
            seed,
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

          if (!ctx.launchToken) {
            write('Proof issued, but missing launch token; cannot claim flag.', 'bad');
            return;
          }

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

      <div class="challenge-panel" style="background: var(--color-accent-glow); border: 1px solid var(--color-accent); margin-bottom: 18px;">
        <strong>Description:</strong> Your goal is to find the internal case proof code that is not visible in the main dashboard. Use the dashboard’s features and network activity to discover hidden data.
      </div>

      <div class="challenge-panel">
        <p class="surface-note">Transparency Portal</p>
        <p class="sdg-poster-text">
          This dashboard tracks confiscations linked to illegal wildlife trade.
          The site claims it only exposes aggregated data, but enforcement failures are often hidden in “internal” records.
        </p>
        <p class="help">Hint: Try using filters or inspecting network requests to see if you can access more detailed information than what is shown in the UI.</p>
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
        seed: ctx.runtimeState.artifact_seed,
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

  function renderRangerRiskEngineChallenge(ctx) {
    setChallengeSurface(`
      ${renderChallengeHeader(
      ctx.runtimeSlug,
      'Ranger Risk Engine',
      'A “sandboxed” risk-score formula service for SDG 15 patrol planning.'
    )}

      <div class="challenge-panel" style="background: var(--color-accent-glow); border: 1px solid var(--color-accent); margin-bottom: 18px;">
        <strong>Description:</strong> Analysts can submit a custom formula to score patrol risk.
        The service claims it safely evaluates formulas server-side.
        Your goal is to obtain the proof code for this challenge and claim the flag.
      </div>

      <div class="challenge-panel">
        <p class="help" style="margin:0;">Hint: If the engine blocks literal tokens, try constructing identifiers at runtime and probing what the evaluator can access.</p>
      </div>

      <div class="challenge-panel" style="background: var(--color-success-bg); border: 1px solid var(--color-success); margin-bottom: 20px;">
        <p class="surface-note" style="color: var(--color-success); margin-bottom: 12px;"><strong>How to solve:</strong></p>
        <ol style="margin-left: 20px; color: var(--color-text-secondary); line-height: 1.8; font-size: 14px;">
          <li><strong>Explore the formula engine</strong> and what it executes.</li>
          <li><strong>Recover a proof code</strong> (32 hex characters).</li>
          <li><strong>Paste the proof</strong> below and click “Claim flag”.</li>
        </ol>
      </div>

      <div class="challenge-grid">
        <div class="challenge-panel">
          <p class="surface-note">Risk formula</p>
          <p class="help">Enter a single JavaScript expression over <code>row</code>. Example: <code>(row.seizures * 12) + (100 - row.paperwork)</code></p>

          <div class="field">
            <label class="label" for="rre-expr">Expression</label>
            <textarea class="input" id="rre-expr" rows="4" spellcheck="false" autocomplete="off"></textarea>
            <p class="help">Hint: “Sandboxed” often just means “best effort”.</p>
          </div>

          <div class="actions">
            <button class="button secondary" id="rre-run" type="button">Run formula</button>
            <button class="button secondary" id="rre-reset" type="button">Reset</button>
          </div>

          <div class="divider"></div>

          <div class="field">
            <label class="label" for="rre-proof">Proof code</label>
            <input class="input" id="rre-proof" name="proof" placeholder="32 hex characters" autocomplete="off" />
            <p class="help">Once you find the proof, claim the flag below.</p>
          </div>
          <div class="actions">
            <button class="button" id="rre-claim" type="button">Claim flag</button>
          </div>
        </div>

        <div class="challenge-panel">
          <div class="output" id="rre-output" role="status" aria-live="polite">Ready…</div>
          <div class="flag hidden" id="rre-flag" aria-label="Claimed flag"></div>
          <div class="divider"></div>
          <p class="surface-note">Raw API response</p>
          <pre class="code-block" id="rre-raw">(no data yet)</pre>
        </div>
      </div>
    `);

    const exprEl = document.getElementById('rre-expr');
    const runBtn = document.getElementById('rre-run');
    const resetBtn = document.getElementById('rre-reset');
    const out = document.getElementById('rre-output');
    const raw = document.getElementById('rre-raw');
    const proofEl = document.getElementById('rre-proof');
    const claimBtn = document.getElementById('rre-claim');
    const flagEl = document.getElementById('rre-flag');

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

    async function runFormula() {
      const expr = (exprEl.value || '').trim();

      const seed = ctx?.runtimeState?.artifact_seed;
      if (!seed || !/^[0-9a-f]{64}$/i.test(String(seed))) {
        write('Missing or invalid runtime seed; cannot query engine.', 'bad');
        return;
      }

      write('Evaluating formula…', 'ok');
      hideFlag();

      try {
        const qs = new URLSearchParams({
          seed,
          slug: ctx.runtimeSlug,
          expr: expr || '',
        });
        const resp = await fetch(`/api/ranger-risk-engine?${qs.toString()}`, {
          method: 'GET',
          credentials: 'omit',
          cache: 'no-store',
        });
        const data = await resp.json().catch(() => null);
        raw.textContent = JSON.stringify(data, null, 2);

        if (!resp.ok) {
          const msg = data?.error || data?.message || `HTTP ${resp.status}`;
          write(`Engine error: ${msg}`, 'bad');
          return;
        }

        const count = Array.isArray(data?.entries) ? data.entries.length : 0;
        write(`OK. Scored ${count} routes. Review raw response.`, 'ok');
      } catch (e) {
        const msg = (e && e.message) ? e.message : 'Unknown error';
        write(`Engine error: ${msg}`, 'bad');
      }
    }

    runBtn?.addEventListener('click', runFormula);
    resetBtn?.addEventListener('click', () => {
      exprEl.value = '(row.seizures * 12) + (100 - row.paperwork) + (row.anomaly ? 25 : 0)';
      raw.textContent = '(no data yet)';
      proofEl.value = '';
      hideFlag();
      write('Ready…');
      exprEl.focus();
    });

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

    // Initialize defaults.
    exprEl.value = '(row.seizures * 12) + (100 - row.paperwork) + (row.anomaly ? 25 : 0)';
    runFormula();
  }

  // ==========================================================================
  // SDG 9 EASY CHALLENGES
  // ==========================================================================

  function renderFactoryMaintenanceChallenge(ctx) {
    setChallengeSurface(`
      ${renderChallengeHeader(ctx.runtimeSlug, 'Factory Maintenance', 'SDG 9 — An industrial control panel in maintenance mode. Find the diagnostic token.')}
      <div class="challenge-panel" style="background: var(--color-success-bg); border: 1px solid var(--color-success); margin-bottom: 20px;">
        <p class="surface-note" style="color: var(--color-success); margin-bottom: 12px;"><strong>How to solve:</strong></p>
        <ol style="margin-left: 20px; color: var(--color-text-secondary); line-height: 1.8; font-size: 14px;">
          <li><strong>Interact with the maintenance API</strong> and observe its responses.</li>
          <li><strong>Find the proof code</strong> (32 hex characters) — the maintenance_token.</li>
          <li><strong>Paste the proof</strong> below and click "Claim flag".</li>
        </ol>
      </div>
      <div class="challenge-panel">
        <p class="surface-note">Maintenance Panel</p>
        <p class="sdg-poster-text">This factory control panel is in scheduled maintenance mode. The system exposes a status API.</p>
        <p class="help">Hint: The API responds differently depending on which HTTP method you use. Not all methods return the same data.</p>
        <div class="actions">
          <button class="button secondary" id="fm-status" type="button">Check Status (GET)</button>
          <button class="button secondary" id="fm-post" type="button">Submit Override (POST)</button>
        </div>
        <pre class="code-block" id="fm-raw">(no data yet)</pre>
      </div>
      <div class="divider"></div>
      <div class="challenge-grid">
        <div class="challenge-panel">
          <div class="field">
            <label class="label" for="fm-proof">Proof code</label>
            <input class="input" id="fm-proof" name="proof" placeholder="32 hex characters" autocomplete="off" />
          </div>
          <div class="actions">
            <button class="button" id="fm-claim" type="button">Claim flag</button>
            <button class="button secondary" id="fm-reset" type="button">Reset</button>
          </div>
        </div>
        <div class="challenge-panel">
          <div class="output" id="fm-output" role="status" aria-live="polite">Waiting for proof…</div>
          <div class="flag hidden" id="fm-flag" aria-label="Claimed flag"></div>
        </div>
      </div>
    `);
    const raw = document.getElementById('fm-raw');
    const out = document.getElementById('fm-output');
    const flagEl = document.getElementById('fm-flag');
    const proofEl = document.getElementById('fm-proof');
    function write(m, k) { out.classList.remove('ok', 'bad'); if (k) out.classList.add(k); out.textContent = m; }
    function showFlag(f) { flagEl.textContent = f; flagEl.classList.remove('hidden'); }
    function hideFlag() { flagEl.textContent = ''; flagEl.classList.add('hidden'); }
    async function doFetch(method) {
      const qs = new URLSearchParams({ seed: ctx.runtimeState.artifact_seed });
      try {
        const resp = await fetch('/api/factory-maintenance?' + qs.toString(), { method, credentials: 'omit', cache: 'no-store' });
        const data = await resp.json().catch(() => null);
        raw.textContent = JSON.stringify(data, null, 2);
        write(resp.ok ? 'Response received. Check raw output.' : 'Error: ' + (data?.error || resp.status), resp.ok ? 'ok' : 'bad');
      } catch (e) { write('Fetch error: ' + e.message, 'bad'); }
    }
    document.getElementById('fm-status')?.addEventListener('click', () => doFetch('GET'));
    document.getElementById('fm-post')?.addEventListener('click', () => doFetch('POST'));
    document.getElementById('fm-claim')?.addEventListener('click', () => {
      const v = (proofEl.value || '').trim(); if (!v) { write('Paste proof first.', 'bad'); return; } hideFlag();
      (async () => { try { const flag = await claimFlag(ctx.launchToken, v, ctx.runtimeSlug); write('Flag claimed.', 'ok'); showFlag(flag); } catch (e) { write('Claim failed: ' + e.message, 'bad'); } })();
    });
    document.getElementById('fm-reset')?.addEventListener('click', () => { proofEl.value = ''; raw.textContent = '(no data yet)'; hideFlag(); write('Waiting for proof…'); });
  }

  function renderSupplyChainMapChallenge(ctx) {
    setChallengeSurface(`
      ${renderChallengeHeader(ctx.runtimeSlug, 'Supply Chain Map', 'SDG 9 — A global infrastructure supply chain tracker. Not all routes are shown on the map.')}
      <div class="challenge-panel" style="background: var(--color-success-bg); border: 1px solid var(--color-success); margin-bottom: 20px;">
        <p class="surface-note" style="color: var(--color-success); margin-bottom: 12px;"><strong>How to solve:</strong></p>
        <ol style="margin-left: 20px; color: var(--color-text-secondary); line-height: 1.8; font-size: 14px;">
          <li><strong>Load the supply chain data</strong> and compare what the UI shows vs. the raw API response.</li>
          <li><strong>Find the proof code</strong> (32 hex characters) hidden in the data.</li>
          <li><strong>Paste the proof</strong> below and click "Claim flag".</li>
        </ol>
      </div>
      <div class="challenge-panel">
        <p class="surface-note">Active Routes</p>
        <p class="help">Hint: The map only renders routes with status "active". What about other statuses?</p>
        <div class="actions"><button class="button secondary" id="scm-load" type="button">Load Routes</button></div>
        <table class="surface-table" id="scm-table" aria-label="Supply chain routes"><thead><tr><th>Route ID</th><th>Origin</th><th>Destination</th><th>Material</th><th>Tonnage</th></tr></thead><tbody id="scm-tbody"></tbody></table>
      </div>
      <div class="challenge-panel"><p class="surface-note">Raw API response</p><pre class="code-block" id="scm-raw">(no data yet)</pre></div>
      <div class="divider"></div>
      <div class="challenge-grid">
        <div class="challenge-panel">
          <div class="field"><label class="label" for="scm-proof">Proof code</label><input class="input" id="scm-proof" placeholder="32 hex characters" autocomplete="off" /></div>
          <div class="actions"><button class="button" id="scm-claim" type="button">Claim flag</button><button class="button secondary" id="scm-reset" type="button">Reset</button></div>
        </div>
        <div class="challenge-panel">
          <div class="output" id="scm-output" role="status" aria-live="polite">Waiting for proof…</div>
          <div class="flag hidden" id="scm-flag" aria-label="Claimed flag"></div>
        </div>
      </div>
    `);
    const raw = document.getElementById('scm-raw'), tbody = document.getElementById('scm-tbody'), out = document.getElementById('scm-output'), flagEl = document.getElementById('scm-flag'), proofEl = document.getElementById('scm-proof');
    function write(m, k) { out.classList.remove('ok', 'bad'); if (k) out.classList.add(k); out.textContent = m; }
    function showFlag(f) { flagEl.textContent = f; flagEl.classList.remove('hidden'); }
    function hideFlag() { flagEl.textContent = ''; flagEl.classList.add('hidden'); }
    document.getElementById('scm-load')?.addEventListener('click', async () => {
      const qs = new URLSearchParams({ seed: ctx.runtimeState.artifact_seed });
      try {
        const resp = await fetch('/api/supply-chain-map?' + qs, { credentials: 'omit', cache: 'no-store' });
        const data = await resp.json().catch(() => null);
        raw.textContent = JSON.stringify(data, null, 2);
        tbody.innerHTML = '';
        if (data?.routes) {
          data.routes.filter(r => r.status === 'active').forEach(r => {
            const tr = document.createElement('tr');
            tr.innerHTML = '<td>' + escapeText(r.route_id) + '</td><td>' + escapeText(r.origin) + '</td><td>' + escapeText(r.destination) + '</td><td>' + escapeText(r.material) + '</td><td>' + (r.tonnage || '—') + '</td>';
            tbody.appendChild(tr);
          });
          write('Loaded ' + data.routes.filter(r => r.status === 'active').length + ' active routes. Are there others?', 'ok');
        }
      } catch (e) { write('Error: ' + e.message, 'bad'); }
    });
    document.getElementById('scm-claim')?.addEventListener('click', () => {
      const v = (proofEl.value || '').trim(); if (!v) { write('Paste proof first.', 'bad'); return; } hideFlag();
      (async () => { try { const flag = await claimFlag(ctx.launchToken, v, ctx.runtimeSlug); write('Flag claimed.', 'ok'); showFlag(flag); } catch (e) { write('Claim failed: ' + e.message, 'bad'); } })();
    });
    document.getElementById('scm-reset')?.addEventListener('click', () => { proofEl.value = ''; raw.textContent = '(no data yet)'; tbody.innerHTML = ''; hideFlag(); write('Waiting for proof…'); });
  }

  function renderLegacyModemChallenge(ctx) {
    setChallengeSurface(`
      ${renderChallengeHeader(ctx.runtimeSlug, 'Legacy Modem', 'SDG 9 — A legacy modem admin panel. Authenticate to retrieve diagnostics.')}
      <div class="challenge-panel" style="background: var(--color-success-bg); border: 1px solid var(--color-success); margin-bottom: 20px;">
        <p class="surface-note" style="color: var(--color-success); margin-bottom: 12px;"><strong>How to solve:</strong></p>
        <ol style="margin-left: 20px; color: var(--color-text-secondary); line-height: 1.8; font-size: 14px;">
          <li><strong>Find the default credentials</strong> for the legacy modem admin panel.</li>
          <li><strong>Authenticate</strong> and retrieve the diagnostic token (32 hex characters).</li>
          <li><strong>Paste the proof</strong> below and click "Claim flag".</li>
        </ol>
      </div>
      <div class="challenge-panel">
        <p class="surface-note">LegacyModem-9600 Admin Panel</p>
        <p class="sdg-poster-text">This modem was deployed as part of the original SDG 9 rural connectivity project. It still uses HTTP Basic authentication.</p>
        <!-- DEFAULT CREDENTIALS: admin / infra2030 — TODO: remove before production -->
        <p class="help">Hint: Legacy infrastructure often ships with default credentials. Check the page source for clues.</p>
        <p class="help" style="font-size:11px; opacity:0.5;">Firmware: LM-9600-v1.2.3 | Default user: admin | Setup guide ref: infra2030-manual.pdf</p>
        <div class="actions"><button class="button secondary" id="lm-connect" type="button">Connect (no auth)</button></div>
        <pre class="code-block" id="lm-raw">(no data yet)</pre>
      </div>
      <div class="divider"></div>
      <div class="challenge-grid">
        <div class="challenge-panel">
          <div class="field"><label class="label" for="lm-proof">Proof code</label><input class="input" id="lm-proof" placeholder="32 hex characters" autocomplete="off" /></div>
          <div class="actions"><button class="button" id="lm-claim" type="button">Claim flag</button><button class="button secondary" id="lm-reset" type="button">Reset</button></div>
        </div>
        <div class="challenge-panel">
          <div class="output" id="lm-output" role="status" aria-live="polite">Waiting for proof…</div>
          <div class="flag hidden" id="lm-flag" aria-label="Claimed flag"></div>
        </div>
      </div>
    `);
    const raw = document.getElementById('lm-raw'), out = document.getElementById('lm-output'), flagEl = document.getElementById('lm-flag'), proofEl = document.getElementById('lm-proof');
    function write(m, k) { out.classList.remove('ok', 'bad'); if (k) out.classList.add(k); out.textContent = m; }
    function showFlag(f) { flagEl.textContent = f; flagEl.classList.remove('hidden'); }
    function hideFlag() { flagEl.textContent = ''; flagEl.classList.add('hidden'); }
    document.getElementById('lm-connect')?.addEventListener('click', async () => {
      const qs = new URLSearchParams({ seed: ctx.runtimeState.artifact_seed });
      try {
        const resp = await fetch('/api/legacy-modem?' + qs, { credentials: 'omit', cache: 'no-store' });
        const data = await resp.json().catch(() => null);
        raw.textContent = JSON.stringify(data, null, 2);
        write(resp.ok ? 'Connected.' : 'Auth required: ' + JSON.stringify(data?.error || resp.status), resp.ok ? 'ok' : 'bad');
      } catch (e) { write('Error: ' + e.message, 'bad'); }
    });
    document.getElementById('lm-claim')?.addEventListener('click', () => {
      const v = (proofEl.value || '').trim(); if (!v) { write('Paste proof first.', 'bad'); return; } hideFlag();
      (async () => { try { const flag = await claimFlag(ctx.launchToken, v, ctx.runtimeSlug); write('Flag claimed.', 'ok'); showFlag(flag); } catch (e) { write('Claim failed: ' + e.message, 'bad'); } })();
    });
    document.getElementById('lm-reset')?.addEventListener('click', () => { proofEl.value = ''; raw.textContent = '(no data yet)'; hideFlag(); write('Waiting for proof…'); });
  }

  // ==========================================================================
  // SDG 9 MEDIUM CHALLENGES
  // ==========================================================================

  function renderIotDashboardChallenge(ctx) {
    setChallengeSurface(`
      ${renderChallengeHeader(ctx.runtimeSlug, 'IoT Dashboard', 'SDG 9 — Industrial IoT sensor dashboard. Access the restricted admin device.')}
      <div class="challenge-panel" style="background: var(--color-accent-glow); border: 1px solid var(--color-accent); margin-bottom: 18px;">
        <strong>Description:</strong> The dashboard lists public sensor devices. An "admin" device holds calibration secrets, but direct access to it is blocked. Find a way around the access check.
      </div>
      <div class="challenge-panel">
        <p class="surface-note">Sensor Dashboard</p>
        <p class="help">Hint: The API blocks requests where device_id equals "admin". But what if the parameter appears more than once in the URL?</p>
        <div class="actions">
          <button class="button secondary" id="iot-list" type="button">List Devices</button>
          <button class="button secondary" id="iot-admin" type="button">Request Admin (blocked)</button>
        </div>
        <pre class="code-block" id="iot-raw">(no data yet)</pre>
      </div>
      <div class="divider"></div>
      <div class="challenge-grid">
        <div class="challenge-panel">
          <div class="field"><label class="label" for="iot-proof">Proof code</label><input class="input" id="iot-proof" placeholder="32 hex characters" autocomplete="off" /></div>
          <div class="actions"><button class="button" id="iot-claim" type="button">Claim flag</button><button class="button secondary" id="iot-reset" type="button">Reset</button></div>
        </div>
        <div class="challenge-panel">
          <div class="output" id="iot-output" role="status" aria-live="polite">Waiting for proof…</div>
          <div class="flag hidden" id="iot-flag" aria-label="Claimed flag"></div>
        </div>
      </div>
    `);
    const raw = document.getElementById('iot-raw'), out = document.getElementById('iot-output'), flagEl = document.getElementById('iot-flag'), proofEl = document.getElementById('iot-proof');
    function write(m, k) { out.classList.remove('ok', 'bad'); if (k) out.classList.add(k); out.textContent = m; }
    function showFlag(f) { flagEl.textContent = f; flagEl.classList.remove('hidden'); }
    function hideFlag() { flagEl.textContent = ''; flagEl.classList.add('hidden'); }
    document.getElementById('iot-list')?.addEventListener('click', async () => {
      const qs = new URLSearchParams({ seed: ctx.runtimeState.artifact_seed });
      try { const resp = await fetch('/api/iot-dashboard?' + qs, { credentials: 'omit', cache: 'no-store' }); const data = await resp.json().catch(() => null); raw.textContent = JSON.stringify(data, null, 2); write(resp.ok ? 'Devices loaded.' : 'Error', 'ok'); } catch (e) { write('Error: ' + e.message, 'bad'); }
    });
    document.getElementById('iot-admin')?.addEventListener('click', async () => {
      const qs = new URLSearchParams({ seed: ctx.runtimeState.artifact_seed, device_id: 'admin' });
      try { const resp = await fetch('/api/iot-dashboard?' + qs, { credentials: 'omit', cache: 'no-store' }); const data = await resp.json().catch(() => null); raw.textContent = JSON.stringify(data, null, 2); write(resp.ok ? 'Admin data returned!' : 'Blocked: ' + (data?.error || resp.status), resp.ok ? 'ok' : 'bad'); } catch (e) { write('Error: ' + e.message, 'bad'); }
    });
    document.getElementById('iot-claim')?.addEventListener('click', () => { const v = (proofEl.value || '').trim(); if (!v) { write('Paste proof first.', 'bad'); return; } hideFlag(); (async () => { try { const flag = await claimFlag(ctx.launchToken, v, ctx.runtimeSlug); write('Flag claimed.', 'ok'); showFlag(flag); } catch (e) { write('Claim failed: ' + e.message, 'bad'); } })(); });
    document.getElementById('iot-reset')?.addEventListener('click', () => { proofEl.value = ''; raw.textContent = '(no data yet)'; hideFlag(); write('Waiting for proof…'); });
  }

  function renderSmartCityGridChallenge(ctx) {
    setChallengeSurface(`
      ${renderChallengeHeader(ctx.runtimeSlug, 'Smart City Grid', 'SDG 9 — Smart city infrastructure grid. Forge a valid authentication signature.')}
      <div class="challenge-panel" style="background: var(--color-accent-glow); border: 1px solid var(--color-accent); margin-bottom: 18px;">
        <strong>Description:</strong> Grid control requires a signed request. The signature is <code>md5(timestamp + secret)</code>. A debug endpoint leaks partial information. Recover the full secret and forge a valid signature.
      </div>
      <div class="challenge-panel">
        <p class="help">Hint: The secret is 8 hex characters. The debug endpoint reveals 6 of them. Brute-force the last 2 (only 256 possibilities).</p>
        <div class="actions">
          <button class="button secondary" id="scg-status" type="button">Grid Status</button>
          <button class="button secondary" id="scg-debug" type="button">Debug Info</button>
        </div>
        <div class="field" style="margin-top:12px;">
          <label class="label" for="scg-sig">Signature (md5 hex)</label>
          <input class="input" id="scg-sig" placeholder="32-char md5 hash" autocomplete="off" />
        </div>
        <div class="actions"><button class="button secondary" id="scg-auth" type="button">Authenticate</button></div>
        <pre class="code-block" id="scg-raw">(no data yet)</pre>
      </div>
      <div class="divider"></div>
      <div class="challenge-grid">
        <div class="challenge-panel">
          <div class="field"><label class="label" for="scg-proof">Proof code</label><input class="input" id="scg-proof" placeholder="32 hex characters" autocomplete="off" /></div>
          <div class="actions"><button class="button" id="scg-claim" type="button">Claim flag</button><button class="button secondary" id="scg-reset" type="button">Reset</button></div>
        </div>
        <div class="challenge-panel">
          <div class="output" id="scg-output" role="status" aria-live="polite">Waiting for proof…</div>
          <div class="flag hidden" id="scg-flag" aria-label="Claimed flag"></div>
        </div>
      </div>
    `);
    const raw = document.getElementById('scg-raw'), out = document.getElementById('scg-output'), flagEl = document.getElementById('scg-flag'), proofEl = document.getElementById('scg-proof'), sigEl = document.getElementById('scg-sig');
    function write(m, k) { out.classList.remove('ok', 'bad'); if (k) out.classList.add(k); out.textContent = m; }
    function showFlag(f) { flagEl.textContent = f; flagEl.classList.remove('hidden'); }
    function hideFlag() { flagEl.textContent = ''; flagEl.classList.add('hidden'); }
    async function apiCall(action, extra) {
      const params = { seed: ctx.runtimeState.artifact_seed, action }; if (extra) Object.assign(params, extra);
      const qs = new URLSearchParams(params);
      try { const resp = await fetch('/api/smart-city-grid?' + qs, { credentials: 'omit', cache: 'no-store' }); const data = await resp.json().catch(() => null); raw.textContent = JSON.stringify(data, null, 2); write(resp.ok ? 'Response received.' : 'Error: ' + (data?.error || resp.status), resp.ok ? 'ok' : 'bad'); } catch (e) { write('Error: ' + e.message, 'bad'); }
    }
    document.getElementById('scg-status')?.addEventListener('click', () => apiCall('status'));
    document.getElementById('scg-debug')?.addEventListener('click', () => apiCall('debug'));
    document.getElementById('scg-auth')?.addEventListener('click', () => { const s = (sigEl.value || '').trim(); if (!s) { write('Enter a signature.', 'bad'); return; } apiCall('authenticate', { signature: s }); });
    document.getElementById('scg-claim')?.addEventListener('click', () => { const v = (proofEl.value || '').trim(); if (!v) { write('Paste proof first.', 'bad'); return; } hideFlag(); (async () => { try { const flag = await claimFlag(ctx.launchToken, v, ctx.runtimeSlug); write('Flag claimed.', 'ok'); showFlag(flag); } catch (e) { write('Claim failed: ' + e.message, 'bad'); } })(); });
    document.getElementById('scg-reset')?.addEventListener('click', () => { proofEl.value = ''; sigEl.value = ''; raw.textContent = '(no data yet)'; hideFlag(); write('Waiting for proof…'); });
  }

  function renderDroneFlightPathChallenge(ctx) {
    setChallengeSurface(`
      ${renderChallengeHeader(ctx.runtimeSlug, 'Drone Flight Path', 'SDG 9 — Drone delivery fleet controller. Escalate to admin privileges via the flight plan API.')}
      <div class="challenge-panel" style="background: var(--color-accent-glow); border: 1px solid var(--color-accent); margin-bottom: 18px;">
        <strong>Description:</strong> Submit a JSON flight plan to register a delivery route. The system merges your plan into the drone state object. Admin flights reveal restricted corridor data. Can you escalate your privileges?
      </div>
      <div class="challenge-panel">
        <p class="help">Hint: The API uses a naive object merge. Certain special JSON keys can modify the prototype chain or overwrite internal properties.</p>
        <div class="actions"><button class="button secondary" id="dfp-info" type="button">Get Info (GET)</button></div>
        <div class="field" style="margin-top:12px;">
          <label class="label" for="dfp-body">Flight Plan JSON</label>
          <textarea class="input" id="dfp-body" rows="5" spellcheck="false">{"drone_id": "DRN-007", "waypoints": [{"lat": 6.5, "lng": 3.4, "alt": 120}]}</textarea>
        </div>
        <div class="actions"><button class="button secondary" id="dfp-send" type="button">Submit Flight Plan (POST)</button></div>
        <pre class="code-block" id="dfp-raw">(no data yet)</pre>
      </div>
      <div class="divider"></div>
      <div class="challenge-grid">
        <div class="challenge-panel">
          <div class="field"><label class="label" for="dfp-proof">Proof code</label><input class="input" id="dfp-proof" placeholder="32 hex characters" autocomplete="off" /></div>
          <div class="actions"><button class="button" id="dfp-claim" type="button">Claim flag</button><button class="button secondary" id="dfp-reset" type="button">Reset</button></div>
        </div>
        <div class="challenge-panel">
          <div class="output" id="dfp-output" role="status" aria-live="polite">Waiting for proof…</div>
          <div class="flag hidden" id="dfp-flag" aria-label="Claimed flag"></div>
        </div>
      </div>
    `);
    const raw = document.getElementById('dfp-raw'), out = document.getElementById('dfp-output'), flagEl = document.getElementById('dfp-flag'), proofEl = document.getElementById('dfp-proof'), bodyEl = document.getElementById('dfp-body');
    function write(m, k) { out.classList.remove('ok', 'bad'); if (k) out.classList.add(k); out.textContent = m; }
    function showFlag(f) { flagEl.textContent = f; flagEl.classList.remove('hidden'); }
    function hideFlag() { flagEl.textContent = ''; flagEl.classList.add('hidden'); }
    document.getElementById('dfp-info')?.addEventListener('click', async () => {
      const qs = new URLSearchParams({ seed: ctx.runtimeState.artifact_seed });
      try { const resp = await fetch('/api/drone-flight-path?' + qs, { credentials: 'omit', cache: 'no-store' }); const data = await resp.json().catch(() => null); raw.textContent = JSON.stringify(data, null, 2); write('Info loaded.', 'ok'); } catch (e) { write('Error: ' + e.message, 'bad'); }
    });
    document.getElementById('dfp-send')?.addEventListener('click', async () => {
      const qs = new URLSearchParams({ seed: ctx.runtimeState.artifact_seed });
      const bodyStr = (bodyEl.value || '').trim();
      try { const resp = await fetch('/api/drone-flight-path?' + qs, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: bodyStr, credentials: 'omit', cache: 'no-store' }); const data = await resp.json().catch(() => null); raw.textContent = JSON.stringify(data, null, 2); write(resp.ok ? (data?.access === 'ADMIN' ? 'ADMIN access granted!' : 'Standard access.') : 'Error: ' + (data?.error || resp.status), resp.ok ? 'ok' : 'bad'); } catch (e) { write('Error: ' + e.message, 'bad'); }
    });
    document.getElementById('dfp-claim')?.addEventListener('click', () => { const v = (proofEl.value || '').trim(); if (!v) { write('Paste proof first.', 'bad'); return; } hideFlag(); (async () => { try { const flag = await claimFlag(ctx.launchToken, v, ctx.runtimeSlug); write('Flag claimed.', 'ok'); showFlag(flag); } catch (e) { write('Claim failed: ' + e.message, 'bad'); } })(); });
    document.getElementById('dfp-reset')?.addEventListener('click', () => { proofEl.value = ''; raw.textContent = '(no data yet)'; hideFlag(); write('Waiting for proof…'); });
  }

  // ==========================================================================
  // SDG 9 HARD CHALLENGES
  // ==========================================================================

  function renderChemicalPlantChallenge(ctx) {
    setChallengeSurface(`
      ${renderChallengeHeader(ctx.runtimeSlug, 'Chemical Plant', 'SDG 9 — SCADA interface with rolling XOR encryption. Reverse the key and forge a command.')}
      <div class="challenge-panel" style="background: var(--color-accent-glow); border: 1px solid var(--color-accent); margin-bottom: 18px;">
        <strong>Description:</strong> The plant control system encrypts commands with a rolling XOR key. You are given a known plaintext/ciphertext pair. Recover the key stream and encrypt the emergency command to gain diagnostic access.
      </div>
      <div class="challenge-panel">
        <p class="help">Hints: XOR is its own inverse. The key mutates every 4 bytes via an LFSR step. Use the "keyhint" action for a longer sample.</p>
        <div class="actions">
          <button class="button secondary" id="cp-status" type="button">Get Status + Sample</button>
          <button class="button secondary" id="cp-keyhint" type="button">Get Key Hint</button>
        </div>
        <div class="field" style="margin-top:12px;">
          <label class="label" for="cp-payload">Encrypted Command (hex)</label>
          <input class="input" id="cp-payload" placeholder="hex-encoded encrypted EMERGENCY_DUMP" autocomplete="off" />
        </div>
        <div class="actions"><button class="button secondary" id="cp-send" type="button">Send Command (POST)</button></div>
        <pre class="code-block" id="cp-raw">(no data yet)</pre>
      </div>
      <div class="divider"></div>
      <div class="challenge-grid">
        <div class="challenge-panel">
          <div class="field"><label class="label" for="cp-proof">Proof code</label><input class="input" id="cp-proof" placeholder="32 hex characters" autocomplete="off" /></div>
          <div class="actions"><button class="button" id="cp-claim" type="button">Claim flag</button><button class="button secondary" id="cp-reset" type="button">Reset</button></div>
        </div>
        <div class="challenge-panel">
          <div class="output" id="cp-output" role="status" aria-live="polite">Waiting for proof…</div>
          <div class="flag hidden" id="cp-flag" aria-label="Claimed flag"></div>
        </div>
      </div>
    `);
    const raw = document.getElementById('cp-raw'), out = document.getElementById('cp-output'), flagEl = document.getElementById('cp-flag'), proofEl = document.getElementById('cp-proof'), payloadEl = document.getElementById('cp-payload');
    function write(m, k) { out.classList.remove('ok', 'bad'); if (k) out.classList.add(k); out.textContent = m; }
    function showFlag(f) { flagEl.textContent = f; flagEl.classList.remove('hidden'); }
    function hideFlag() { flagEl.textContent = ''; flagEl.classList.add('hidden'); }
    async function apiGet(action) { const qs = new URLSearchParams({ seed: ctx.runtimeState.artifact_seed, action }); try { const resp = await fetch('/api/chemical-plant?' + qs, { credentials: 'omit', cache: 'no-store' }); const data = await resp.json().catch(() => null); raw.textContent = JSON.stringify(data, null, 2); write('Response received.', 'ok'); } catch (e) { write('Error: ' + e.message, 'bad'); } }
    document.getElementById('cp-status')?.addEventListener('click', () => apiGet('status'));
    document.getElementById('cp-keyhint')?.addEventListener('click', () => apiGet('keyhint'));
    document.getElementById('cp-send')?.addEventListener('click', async () => {
      const p = (payloadEl.value || '').trim(); if (!p) { write('Enter payload.', 'bad'); return; }
      const qs = new URLSearchParams({ seed: ctx.runtimeState.artifact_seed, action: 'command' });
      try { const resp = await fetch('/api/chemical-plant?' + qs, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ payload: p }), credentials: 'omit', cache: 'no-store' }); const data = await resp.json().catch(() => null); raw.textContent = JSON.stringify(data, null, 2); write(resp.ok ? 'Command accepted!' : 'Rejected: ' + (data?.error || resp.status), resp.ok ? 'ok' : 'bad'); } catch (e) { write('Error: ' + e.message, 'bad'); }
    });
    document.getElementById('cp-claim')?.addEventListener('click', () => { const v = (proofEl.value || '').trim(); if (!v) { write('Paste proof first.', 'bad'); return; } hideFlag(); (async () => { try { const flag = await claimFlag(ctx.launchToken, v, ctx.runtimeSlug); write('Flag claimed.', 'ok'); showFlag(flag); } catch (e) { write('Claim failed: ' + e.message, 'bad'); } })(); });
    document.getElementById('cp-reset')?.addEventListener('click', () => { proofEl.value = ''; payloadEl.value = ''; raw.textContent = '(no data yet)'; hideFlag(); write('Waiting for proof…'); });
  }

  function renderSatelliteUplinkChallenge(ctx) {
    setChallengeSurface(`
      ${renderChallengeHeader(ctx.runtimeSlug, 'Satellite Uplink', 'SDG 9 — Satellite communication terminal with a custom binary protocol. Craft a valid admin packet.')}
      <div class="challenge-panel" style="background: var(--color-accent-glow); border: 1px solid var(--color-accent); margin-bottom: 18px;">
        <strong>Description:</strong> The uplink accepts hex-encoded binary packets with a specific structure: magic bytes, version, command, payload, and checksum. Craft a packet with CMD=0x42 and the correct authorization payload to dump admin data.
      </div>
      <div class="challenge-panel">
        <p class="help">Hints: Start with the info endpoint to see the protocol spec and a sample packet. Reverse-engineer the sample, then build your own admin packet with a valid checksum.</p>
        <div class="actions"><button class="button secondary" id="su-info" type="button">Protocol Info</button></div>
        <div class="field" style="margin-top:12px;">
          <label class="label" for="su-packet">Binary Packet (hex)</label>
          <input class="input" id="su-packet" placeholder="hex-encoded packet" autocomplete="off" />
        </div>
        <div class="actions"><button class="button secondary" id="su-send" type="button">Send Packet (POST)</button></div>
        <pre class="code-block" id="su-raw">(no data yet)</pre>
      </div>
      <div class="divider"></div>
      <div class="challenge-grid">
        <div class="challenge-panel">
          <div class="field"><label class="label" for="su-proof">Proof code</label><input class="input" id="su-proof" placeholder="32 hex characters" autocomplete="off" /></div>
          <div class="actions"><button class="button" id="su-claim" type="button">Claim flag</button><button class="button secondary" id="su-reset" type="button">Reset</button></div>
        </div>
        <div class="challenge-panel">
          <div class="output" id="su-output" role="status" aria-live="polite">Waiting for proof…</div>
          <div class="flag hidden" id="su-flag" aria-label="Claimed flag"></div>
        </div>
      </div>
    `);
    const raw = document.getElementById('su-raw'), out = document.getElementById('su-output'), flagEl = document.getElementById('su-flag'), proofEl = document.getElementById('su-proof'), packetEl = document.getElementById('su-packet');
    function write(m, k) { out.classList.remove('ok', 'bad'); if (k) out.classList.add(k); out.textContent = m; }
    function showFlag(f) { flagEl.textContent = f; flagEl.classList.remove('hidden'); }
    function hideFlag() { flagEl.textContent = ''; flagEl.classList.add('hidden'); }
    document.getElementById('su-info')?.addEventListener('click', async () => { const qs = new URLSearchParams({ seed: ctx.runtimeState.artifact_seed, action: 'info' }); try { const resp = await fetch('/api/satellite-uplink?' + qs, { credentials: 'omit', cache: 'no-store' }); const data = await resp.json().catch(() => null); raw.textContent = JSON.stringify(data, null, 2); write('Protocol info loaded.', 'ok'); } catch (e) { write('Error: ' + e.message, 'bad'); } });
    document.getElementById('su-send')?.addEventListener('click', async () => {
      const p = (packetEl.value || '').trim(); if (!p) { write('Enter packet hex.', 'bad'); return; }
      const qs = new URLSearchParams({ seed: ctx.runtimeState.artifact_seed, action: 'send' });
      try { const resp = await fetch('/api/satellite-uplink?' + qs, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ packet: p }), credentials: 'omit', cache: 'no-store' }); const data = await resp.json().catch(() => null); raw.textContent = JSON.stringify(data, null, 2); write(resp.ok ? 'Packet accepted!' : 'Rejected: ' + (data?.error || resp.status), resp.ok ? 'ok' : 'bad'); } catch (e) { write('Error: ' + e.message, 'bad'); }
    });
    document.getElementById('su-claim')?.addEventListener('click', () => { const v = (proofEl.value || '').trim(); if (!v) { write('Paste proof first.', 'bad'); return; } hideFlag(); (async () => { try { const flag = await claimFlag(ctx.launchToken, v, ctx.runtimeSlug); write('Flag claimed.', 'ok'); showFlag(flag); } catch (e) { write('Claim failed: ' + e.message, 'bad'); } })(); });
    document.getElementById('su-reset')?.addEventListener('click', () => { proofEl.value = ''; packetEl.value = ''; raw.textContent = '(no data yet)'; hideFlag(); write('Waiting for proof…'); });
  }

  function renderBioLabAirlockChallenge(ctx) {
    setChallengeSurface(`
      ${renderChallengeHeader(ctx.runtimeSlug, 'Bio-Lab Airlock', 'SDG 9 — Specimen database with blind extraction. Discover a hidden field and extract its value.')}
      <div class="challenge-panel" style="background: var(--color-accent-glow); border: 1px solid var(--color-accent); margin-bottom: 18px;">
        <strong>Description:</strong> The specimen database has a documented schema, but one record contains an undocumented field with a randomized name. The field's value is the proof. Use NoSQL-style operators to discover the field name, identify which record has it, and extract the value character by character.
      </div>
      <div class="challenge-panel">
        <p class="help">Hints: Use ?action=fields to list all field names. Use $exists in queries to find which record has the field. Use the "extract" action with regex to test the value character by character.</p>
        <div class="actions">
          <button class="button secondary" id="bla-schema" type="button">Schema</button>
          <button class="button secondary" id="bla-fields" type="button">All Fields</button>
        </div>
        <div class="field" style="margin-top:12px;">
          <label class="label" for="bla-query">Query Filter JSON</label>
          <textarea class="input" id="bla-query" rows="3" spellcheck="false">{"biosafety_level": {"$gte": 3}}</textarea>
        </div>
        <div class="actions"><button class="button secondary" id="bla-qsend" type="button">Query (POST)</button></div>
        <div class="divider"></div>
        <p class="surface-note">Blind Extraction</p>
        <div class="field"><label class="label" for="bla-rid">Record ID</label><input class="input" id="bla-rid" value="BIO-005" autocomplete="off" /></div>
        <div class="field"><label class="label" for="bla-regex">Regex pattern</label><input class="input" id="bla-regex" placeholder="^[0-9a-f]" autocomplete="off" /></div>
        <div class="actions"><button class="button secondary" id="bla-extract" type="button">Test Regex</button></div>
        <pre class="code-block" id="bla-raw">(no data yet)</pre>
      </div>
      <div class="divider"></div>
      <div class="challenge-grid">
        <div class="challenge-panel">
          <div class="field"><label class="label" for="bla-proof">Proof code</label><input class="input" id="bla-proof" placeholder="32 hex characters" autocomplete="off" /></div>
          <div class="actions"><button class="button" id="bla-claim" type="button">Claim flag</button><button class="button secondary" id="bla-reset" type="button">Reset</button></div>
        </div>
        <div class="challenge-panel">
          <div class="output" id="bla-output" role="status" aria-live="polite">Waiting for proof…</div>
          <div class="flag hidden" id="bla-flag" aria-label="Claimed flag"></div>
        </div>
      </div>
    `);
    const raw = document.getElementById('bla-raw'), out = document.getElementById('bla-output'), flagEl = document.getElementById('bla-flag'), proofEl = document.getElementById('bla-proof');
    function write(m, k) { out.classList.remove('ok', 'bad'); if (k) out.classList.add(k); out.textContent = m; }
    function showFlag(f) { flagEl.textContent = f; flagEl.classList.remove('hidden'); }
    function hideFlag() { flagEl.textContent = ''; flagEl.classList.add('hidden'); }
    async function apiGet(action) { const qs = new URLSearchParams({ seed: ctx.runtimeState.artifact_seed, action }); try { const resp = await fetch('/api/bio-lab-airlock?' + qs, { credentials: 'omit', cache: 'no-store' }); const data = await resp.json().catch(() => null); raw.textContent = JSON.stringify(data, null, 2); write('Response received.', 'ok'); } catch (e) { write('Error: ' + e.message, 'bad'); } }
    document.getElementById('bla-schema')?.addEventListener('click', () => apiGet('schema'));
    document.getElementById('bla-fields')?.addEventListener('click', () => apiGet('fields'));
    document.getElementById('bla-qsend')?.addEventListener('click', async () => {
      const q = (document.getElementById('bla-query').value || '').trim();
      const qs = new URLSearchParams({ seed: ctx.runtimeState.artifact_seed, action: 'query' });
      try { const resp = await fetch('/api/bio-lab-airlock?' + qs, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ filter: JSON.parse(q) }), credentials: 'omit', cache: 'no-store' }); const data = await resp.json().catch(() => null); raw.textContent = JSON.stringify(data, null, 2); write('Query returned ' + (data?.count || 0) + ' results.', 'ok'); } catch (e) { write('Error: ' + e.message, 'bad'); }
    });
    document.getElementById('bla-extract')?.addEventListener('click', async () => {
      const rid = (document.getElementById('bla-rid').value || '').trim();
      const regex = (document.getElementById('bla-regex').value || '').trim();
      if (!rid || !regex) { write('Enter record ID and regex.', 'bad'); return; }
      const qs = new URLSearchParams({ seed: ctx.runtimeState.artifact_seed, action: 'extract' });
      try { const resp = await fetch('/api/bio-lab-airlock?' + qs, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ record_id: rid, regex }), credentials: 'omit', cache: 'no-store' }); const data = await resp.json().catch(() => null); raw.textContent = JSON.stringify(data, null, 2); write(data?.match ? 'MATCH: regex matched!' : 'NO MATCH.', data?.match ? 'ok' : 'bad'); } catch (e) { write('Error: ' + e.message, 'bad'); }
    });
    document.getElementById('bla-claim')?.addEventListener('click', () => { const v = (proofEl.value || '').trim(); if (!v) { write('Paste proof first.', 'bad'); return; } hideFlag(); (async () => { try { const flag = await claimFlag(ctx.launchToken, v, ctx.runtimeSlug); write('Flag claimed.', 'ok'); showFlag(flag); } catch (e) { write('Claim failed: ' + e.message, 'bad'); } })(); });
    document.getElementById('bla-reset')?.addEventListener('click', () => { proofEl.value = ''; raw.textContent = '(no data yet)'; hideFlag(); write('Waiting for proof…'); });
  }

  function renderAiOptimizerChallenge(ctx) {
    setChallengeSurface(`
      ${renderChallengeHeader(ctx.runtimeSlug, 'AI Optimizer', 'SDG 9 — Neural network infrastructure optimizer. Reverse the model to find the magic input.')}
      <div class="challenge-panel" style="background: var(--color-accent-glow); border: 1px solid var(--color-accent); margin-bottom: 18px;">
        <strong>Description:</strong> A 2-layer neural network (4→4 ReLU → 1 linear) predicts infrastructure efficiency. You are given the weights, biases, and a target output value. Find an integer input vector [a,b,c,d] that produces exactly the target output.
      </div>
      <div class="challenge-panel">
        <p class="help">Hints: Dump the model weights. Understand which hidden neurons activate (ReLU). Solve the resulting system of linear equations. Try brute-forcing small integer ranges if algebra is difficult.</p>
        <div class="actions">
          <button class="button secondary" id="aio-info" type="button">Info</button>
          <button class="button secondary" id="aio-model" type="button">Dump Model</button>
        </div>
        <div class="field" style="margin-top:12px;">
          <label class="label" for="aio-input">Input Vector [a,b,c,d]</label>
          <input class="input" id="aio-input" placeholder="e.g. [1, 2, -3, 4]" autocomplete="off" />
        </div>
        <div class="actions"><button class="button secondary" id="aio-infer" type="button">Run Inference (POST)</button></div>
        <pre class="code-block" id="aio-raw">(no data yet)</pre>
      </div>
      <div class="divider"></div>
      <div class="challenge-grid">
        <div class="challenge-panel">
          <div class="field"><label class="label" for="aio-proof">Proof code</label><input class="input" id="aio-proof" placeholder="32 hex characters" autocomplete="off" /></div>
          <div class="actions"><button class="button" id="aio-claim" type="button">Claim flag</button><button class="button secondary" id="aio-reset" type="button">Reset</button></div>
        </div>
        <div class="challenge-panel">
          <div class="output" id="aio-output" role="status" aria-live="polite">Waiting for proof…</div>
          <div class="flag hidden" id="aio-flag" aria-label="Claimed flag"></div>
        </div>
      </div>
    `);
    const raw = document.getElementById('aio-raw'), out = document.getElementById('aio-output'), flagEl = document.getElementById('aio-flag'), proofEl = document.getElementById('aio-proof'), inputEl = document.getElementById('aio-input');
    function write(m, k) { out.classList.remove('ok', 'bad'); if (k) out.classList.add(k); out.textContent = m; }
    function showFlag(f) { flagEl.textContent = f; flagEl.classList.remove('hidden'); }
    function hideFlag() { flagEl.textContent = ''; flagEl.classList.add('hidden'); }
    async function apiGet(action) { const qs = new URLSearchParams({ seed: ctx.runtimeState.artifact_seed, action }); try { const resp = await fetch('/api/ai-optimizer?' + qs, { credentials: 'omit', cache: 'no-store' }); const data = await resp.json().catch(() => null); raw.textContent = JSON.stringify(data, null, 2); write('Response received.', 'ok'); } catch (e) { write('Error: ' + e.message, 'bad'); } }
    document.getElementById('aio-info')?.addEventListener('click', () => apiGet('info'));
    document.getElementById('aio-model')?.addEventListener('click', () => apiGet('model'));
    document.getElementById('aio-infer')?.addEventListener('click', async () => {
      const v = (inputEl.value || '').trim(); let arr; try { arr = JSON.parse(v); } catch { write('Invalid JSON array.', 'bad'); return; }
      if (!Array.isArray(arr) || arr.length !== 4) { write('Must be [a,b,c,d].', 'bad'); return; }
      const qs = new URLSearchParams({ seed: ctx.runtimeState.artifact_seed, action: 'infer' });
      try { const resp = await fetch('/api/ai-optimizer?' + qs, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ input: arr }), credentials: 'omit', cache: 'no-store' }); const data = await resp.json().catch(() => null); raw.textContent = JSON.stringify(data, null, 2); write(data?.match ? 'TARGET MATCHED!' : 'Output=' + data?.output + ' (target=' + data?.target + ', diff=' + data?.difference + ')', data?.match ? 'ok' : 'bad'); } catch (e) { write('Error: ' + e.message, 'bad'); }
    });
    document.getElementById('aio-claim')?.addEventListener('click', () => { const v = (proofEl.value || '').trim(); if (!v) { write('Paste proof first.', 'bad'); return; } hideFlag(); (async () => { try { const flag = await claimFlag(ctx.launchToken, v, ctx.runtimeSlug); write('Flag claimed.', 'ok'); showFlag(flag); } catch (e) { write('Claim failed: ' + e.message, 'bad'); } })(); });
    document.getElementById('aio-reset')?.addEventListener('click', () => { proofEl.value = ''; inputEl.value = ''; raw.textContent = '(no data yet)'; hideFlag(); write('Waiting for proof…'); });
  }

  const CHALLENGES = Object.freeze({
    // Default module if slug is unknown
    demo: renderDemoChallenge,
    // SDG 15 challenges
    'hidden-in-plain-sight': renderHiddenInPlainSightChallenge,
    'save-the-species': renderSaveTheSpeciesChallenge,
    'endangered-access': renderEndangeredAccessChallenge,
    'illegal-logging-network': renderIllegalLoggingNetworkChallenge,
    'poacher-supply-chain': renderPoacherSupplyChainChallenge,
    'ranger-risk-engine': renderRangerRiskEngineChallenge,
    // SDG 9 Easy
    'factory-maintenance': renderFactoryMaintenanceChallenge,
    'supply-chain-map': renderSupplyChainMapChallenge,
    'legacy-modem': renderLegacyModemChallenge,
    // SDG 9 Medium
    'iot-dashboard': renderIotDashboardChallenge,
    'smart-city-grid': renderSmartCityGridChallenge,
    'drone-flight-path': renderDroneFlightPathChallenge,
    // SDG 9 Hard
    'chemical-plant': renderChemicalPlantChallenge,
    'satellite-uplink': renderSatelliteUplinkChallenge,
    'bio-lab-airlock': renderBioLabAirlockChallenge,
    'ai-optimizer': renderAiOptimizerChallenge,
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
