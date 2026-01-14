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
 * - artifact_seed is used to derive challenge state, NOT to compute flags
 * 
 * The actual vulnerable challenge surface should be built using artifact_seed
 * to create deterministic, per-team variations. The flag derivation happens
 * server-side only.
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
   * Set to false in production to disable console logging of sensitive data.
   */
  const DEBUG_MODE = true;

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
    const seed = ctx.runtimeState.artifact_seed;

    const userId = simpleHash(seed, 'user_id') % 10000;
    const userName = 'user_' + deriveHex(seed, 'username', 6);
    const apiKey = deriveHex(seed, 'api_key', 16);
    const recordCount = 10 + (simpleHash(seed, 'records') % 90);

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

  function renderSeededVaultChallenge(ctx) {
    // A safe, frontend-only "challenge" template: a deterministic vault that
    // unlocks based on a derived phrase. No flag is computed or shown.
    const seed = ctx.runtimeState.artifact_seed;

    const vaultId = deriveHex(seed, 'vault_id', 8);
    const hintWords = [
      'ember', 'cobalt', 'atlas', 'lumen', 'nova', 'orchid', 'vertex', 'cipher',
      'quartz', 'delta', 'aurora', 'kernel', 'saffron', 'zenith', 'anchor', 'ripple',
    ];
    const w1 = hintWords[simpleHash(seed, 'w1') % hintWords.length];
    const w2 = hintWords[simpleHash(seed, 'w2') % hintWords.length];
    const w3 = hintWords[simpleHash(seed, 'w3') % hintWords.length];
    const expected = `${w1}-${w2}-${w3}-${vaultId.slice(0, 4)}`;

    setChallengeSurface(`
      ${renderChallengeHeader(ctx.runtimeSlug, 'Vault Access Terminal', 'Enter the access phrase to unlock the seeded vault (demo template).')}
      <div class="challenge-grid">
        <div class="challenge-panel">
          <div class="field">
            <label class="label" for="vault-phrase">Access phrase</label>
            <input class="input" id="vault-phrase" name="phrase" placeholder="e.g. ember-cobalt-atlas-1a2b" autocomplete="off" />
            <p class="help">Hint: ${escapeText(w1)} + ${escapeText(w2)} + ${escapeText(w3)} + '-' + 4 hex chars</p>
          </div>
          <div class="actions">
            <button class="button" id="vault-submit" type="button">Check phrase</button>
            <button class="button secondary" id="vault-reset" type="button">Reset</button>
          </div>
        </div>
        <div class="challenge-panel">
          <div class="output" id="vault-output" role="status" aria-live="polite">Waiting for input…</div>
          <p class="surface-note">
            Demo behavior only: unlocking shows a non-sensitive artifact preview.
            Real challenges should verify flags server-side.
          </p>
        </div>
      </div>
    `);

    const input = document.getElementById('vault-phrase');
    const submit = document.getElementById('vault-submit');
    const reset = document.getElementById('vault-reset');
    const out = document.getElementById('vault-output');

    function write(message, kind) {
      out.classList.remove('ok', 'bad');
      if (kind) out.classList.add(kind);
      out.textContent = message;
    }

    submit.addEventListener('click', () => {
      const value = (input.value || '').trim().toLowerCase();
      if (!value) {
        write('Enter a phrase first.', 'bad');
        return;
      }

      if (value === expected) {
        const artifactPreview = deriveHex(seed, 'artifact_preview', 24);
        write(`Unlocked vault ${vaultId}. Artifact preview: ${artifactPreview}…`, 'ok');
        return;
      }

      write('Access denied. Phrase incorrect.', 'bad');
    });

    reset.addEventListener('click', () => {
      input.value = '';
      write('Waiting for input…');
      input.focus();
    });
  }

  const CHALLENGES = Object.freeze({
    // Default module if slug is unknown
    demo: renderDemoChallenge,
    // Example template challenge
    'seeded-vault': renderSeededVaultChallenge,
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
   */
  function deriveHex(seed, salt, length) {
    let result = '';
    for (let i = 0; i < length; i++) {
      const hash = simpleHash(seed, salt + i.toString());
      result += (hash % 16).toString(16);
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
  function showSuccess(runtimeState, route) {
    elements.statusPanel.classList.add('hidden');
    elements.errorPanel.classList.add('hidden');
    elements.runtimeInfo.classList.remove('hidden');

    // Display masked IDs (never show raw artifact_seed in UI)
    elements.infoContest.textContent = maskUUID(runtimeState.contest_id);
    elements.infoChallenge.textContent = maskUUID(runtimeState.challenge_id);
    elements.infoTeam.textContent = maskUUID(runtimeState.team_id);

    // Render the challenge surface selected by runtimeSlug
    renderChallengeSurface(runtimeState, route);
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
  function renderChallengeSurface(runtimeState, route) {
    const runtimeSlug = normalizeSlug(route && route.runtimeSlug);
    const render = CHALLENGES[runtimeSlug] || CHALLENGES.demo;
    render({ runtimeState, route, runtimeSlug });
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

  // ==========================================================================
  // MAIN INITIALIZATION
  // ==========================================================================

  async function initialize() {
    showLoading('Initializing runtime...');

    // Parse route (optional, for future use)
    const route = parseRoute();
    if (DEBUG_MODE && route) {
      console.log('[SDG Runtime] Route:', route);
    }

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
        artifact_seed: runtimeState.artifact_seed,
      });

      // Log in debug mode (REMOVE IN PRODUCTION or redact artifact_seed)
      if (DEBUG_MODE) {
        console.log('[SDG Runtime] Initialized:', {
          contest_id: runtimeState.contest_id,
          challenge_id: runtimeState.challenge_id,
          team_id: runtimeState.team_id,
          // WARNING: In production, do NOT log artifact_seed
          artifact_seed: '[REDACTED - check window.__SDG_RUNTIME in devtools]',
        });
      }

      // Show success UI
      showSuccess(runtimeState, route);

    } catch (error) {
      console.error('[SDG Runtime] Error:', error);

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
