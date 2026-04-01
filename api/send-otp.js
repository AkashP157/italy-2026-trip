const crypto = require('crypto');

const ALLOWED_EMAILS = (process.env.ALLOWED_EMAILS || '').split(',').map(e => e.trim().toLowerCase());
const OTP_SECRET = process.env.OTP_SECRET || 'fallback-secret-change-me';
const RESEND_KEY = process.env.RESEND_KEY || '';

// OTP store (in-memory, fine for serverless cold starts — OTPs are short-lived)
// For production at scale, use Vercel KV. For 2 users this is fine.
const otpStore = globalThis.__otpStore || (globalThis.__otpStore = new Map());

function generateOTP() {
  return crypto.randomInt(100000, 999999).toString();
}

function signToken(email) {
  const payload = JSON.stringify({ email, exp: Date.now() + 7 * 24 * 60 * 60 * 1000 }); // 7 days
  const sig = crypto.createHmac('sha256', OTP_SECRET).update(payload).digest('hex');
  return Buffer.from(payload).toString('base64') + '.' + sig;
}

module.exports = async function handler(req, res) {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { email } = req.body || {};
  if (!email || typeof email !== 'string') {
    return res.status(400).json({ error: 'Email required' });
  }

  const normalized = email.trim().toLowerCase();
  if (!ALLOWED_EMAILS.includes(normalized)) {
    return res.status(403).json({ error: 'Email not authorized' });
  }

  // Rate limit: max 1 OTP per 60 seconds per email
  const existing = otpStore.get(normalized);
  if (existing && Date.now() - existing.created < 60000) {
    return res.status(429).json({ error: 'Please wait 60 seconds before requesting a new code' });
  }

  const otp = generateOTP();
  otpStore.set(normalized, { otp, created: Date.now(), attempts: 0 });

  // Clean up old entries
  for (const [key, val] of otpStore) {
    if (Date.now() - val.created > 600000) otpStore.delete(key); // 10 min expiry
  }

  // Send via Resend
  if (!RESEND_KEY) {
    return res.status(500).json({ error: 'Email service not configured' });
  }

  try {
    const response = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${RESEND_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        from: 'Italy Trip <onboarding@resend.dev>',
        to: [normalized],
        subject: `${otp} — Your Italy 2026 access code`,
        html: `
          <div style="font-family:-apple-system,system-ui,sans-serif;max-width:400px;margin:0 auto;padding:40px 20px;text-align:center">
            <div style="font-size:48px;margin-bottom:16px">🇮🇹</div>
            <h1 style="font-size:20px;font-weight:700;margin-bottom:8px;color:#1a1a1e">Italy 2026 Trip</h1>
            <p style="color:#666;font-size:14px;margin-bottom:24px">Your access code is:</p>
            <div style="font-family:monospace;font-size:36px;font-weight:800;letter-spacing:8px;color:#ff9f0a;background:#1c1c1e;padding:16px 24px;border-radius:12px;display:inline-block">${otp}</div>
            <p style="color:#999;font-size:12px;margin-top:24px">Expires in 10 minutes. Don't share this code.</p>
          </div>
        `
      })
    });

    if (!response.ok) {
      const err = await response.text();
      console.error('Resend error:', err);
      return res.status(500).json({ error: 'Failed to send email' });
    }

    return res.status(200).json({ ok: true, message: 'Code sent' });
  } catch (err) {
    console.error('Send error:', err);
    return res.status(500).json({ error: 'Failed to send email' });
  }
};
