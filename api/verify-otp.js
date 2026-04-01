const crypto = require('crypto');

const OTP_SECRET = process.env.OTP_SECRET || 'fallback-secret-change-me';

const otpStore = globalThis.__otpStore || (globalThis.__otpStore = new Map());

function signToken(email) {
  const payload = JSON.stringify({ email, exp: Date.now() + 7 * 24 * 60 * 60 * 1000 });
  const sig = crypto.createHmac('sha256', OTP_SECRET).update(payload).digest('hex');
  return Buffer.from(payload).toString('base64url') + '.' + sig;
}

function verifyToken(token) {
  if (!token || !token.includes('.')) return null;
  const [b64, sig] = token.split('.');
  try {
    const payload = Buffer.from(b64, 'base64url').toString();
    const expected = crypto.createHmac('sha256', OTP_SECRET).update(payload).digest('hex');
    if (sig !== expected) return null;
    const data = JSON.parse(payload);
    if (data.exp < Date.now()) return null;
    return data;
  } catch { return null; }
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { email, otp, token } = req.body || {};

  // Token validation mode (check existing session)
  if (token) {
    const data = verifyToken(token);
    if (data) return res.status(200).json({ ok: true, valid: true, email: data.email });
    return res.status(401).json({ ok: false, valid: false });
  }

  // OTP verification mode
  if (!email || !otp) {
    return res.status(400).json({ error: 'Email and OTP required' });
  }

  const normalized = email.trim().toLowerCase();
  const stored = otpStore.get(normalized);

  if (!stored) {
    return res.status(400).json({ error: 'No code found. Request a new one.' });
  }

  // Expiry check (10 minutes)
  if (Date.now() - stored.created > 600000) {
    otpStore.delete(normalized);
    return res.status(400).json({ error: 'Code expired. Request a new one.' });
  }

  // Brute force protection (max 5 attempts)
  if (stored.attempts >= 5) {
    otpStore.delete(normalized);
    return res.status(429).json({ error: 'Too many attempts. Request a new code.' });
  }

  stored.attempts++;

  if (stored.otp !== otp.trim()) {
    return res.status(400).json({ error: `Invalid code. ${5 - stored.attempts} attempts left.` });
  }

  // Success — clean up and issue token
  otpStore.delete(normalized);
  const sessionToken = signToken(normalized);

  return res.status(200).json({ ok: true, token: sessionToken, email: normalized });
};
