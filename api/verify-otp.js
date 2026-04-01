const crypto = require('crypto');

const OTP_SECRET = process.env.OTP_SECRET || 'fallback-secret-change-me';

function signOTP(email, otp, expiry) {
  const data = `${email}:${otp}:${expiry}`;
  return crypto.createHmac('sha256', OTP_SECRET).update(data).digest('hex');
}

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

  const { email, otp, challenge, token } = req.body || {};

  // Token validation mode (check existing session)
  if (token) {
    const data = verifyToken(token);
    if (data) return res.status(200).json({ ok: true, valid: true, email: data.email });
    return res.status(401).json({ ok: false, valid: false });
  }

  // OTP verification mode
  if (!otp || !challenge) {
    return res.status(400).json({ error: 'Code and challenge required' });
  }

  // Decode the challenge
  let ch;
  try {
    ch = JSON.parse(Buffer.from(challenge, 'base64url').toString());
  } catch {
    return res.status(400).json({ error: 'Invalid challenge' });
  }

  if (!ch.email || !ch.expiry || !ch.sig) {
    return res.status(400).json({ error: 'Malformed challenge' });
  }

  // Check expiry
  if (Date.now() > ch.expiry) {
    return res.status(400).json({ error: 'Code expired. Request a new one.' });
  }

  // Verify: recompute HMAC(email:otp:expiry) and compare to stored sig
  const expected = signOTP(ch.email, otp.trim(), ch.expiry);
  if (expected !== ch.sig) {
    return res.status(400).json({ error: 'Invalid code. Try again.' });
  }

  // Success — issue session token
  const sessionToken = signToken(ch.email);
  return res.status(200).json({ ok: true, token: sessionToken, email: ch.email });
};
