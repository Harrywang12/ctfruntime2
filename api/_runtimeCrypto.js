const crypto = require('crypto');

function getProofSecret() {
  const secret =
    process.env.PROOF_SECRET_SALT ||
    process.env.RUNTIME_PROOF_SECRET ||
    process.env.PROOF_SECRET ||
    '';
  if (!secret) {
    throw new Error('Missing server secret: set PROOF_SECRET_SALT (or RUNTIME_PROOF_SECRET)');
  }
  return secret;
}

function getFlagSecret() {
  const secret =
    process.env.FLAG_SECRET_SALT ||
    process.env.PROOF_SECRET_SALT ||  // Fallback for backwards compatibility
    process.env.RUNTIME_PROOF_SECRET ||
    '';
  if (!secret) {
    throw new Error('Missing server secret: set FLAG_SECRET_SALT (or PROOF_SECRET_SALT)');
  }
  return secret;
}

function hmacHex(secret, message) {
  return crypto.createHmac('sha256', Buffer.from(String(secret), 'utf8'))
    .update(String(message), 'utf8')
    .digest('hex');
}

function computeProof({ artifactSeed, runtimeSlug }) {
  const secret = getProofSecret();
  const msg = `proof.v2.${artifactSeed}.${runtimeSlug}`;
  return hmacHex(secret, msg).slice(0, 32);
}

function computeFlag({ artifactSeed, runtimeSlug }) {
  const secret = getFlagSecret();
  const msg = `flag:v2:${artifactSeed}:${runtimeSlug}`;
  const body = hmacHex(secret, msg).slice(0, 32);
  return `SDG{${body}}`;
}

module.exports = {
  getProofSecret,
  getFlagSecret,
  hmacHex,
  computeProof,
  computeFlag,
};
