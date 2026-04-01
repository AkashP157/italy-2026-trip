const crypto = require('crypto');

const ALLOWED_EMAILS = (process.env.ALLOWED_EMAILS || '').split(',').map(e => e.trim().toLowerCase()).filter(Boolean);
const OTP_SECRET = process.env.OTP_SECRET || 'fallback-secret-change-me';
const RESEND_KEY = process.env.RESEND_KEY || '';

function generateOTP() {
  return crypto.randomInt(100000, 999999).toString();
}

// Create HMAC of (email + otp + expiry) so verify-otp can validate statelessly
function signOTP(email, otp, expiry) {
  const data = `${email}:${otp}:${expiry}`;
  return crypto.createHmac('sha256', OTP_SECRET).update(data).digest('hex');
}

module.exports = async function handler(req, res) {
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

  const otp = generateOTP();
  const expiry = Date.now() + 10 * 60 * 1000; // 10 minutes
  const signature = signOTP(normalized, otp, expiry);

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

    // Return signed challenge (email + expiry + sig) — OTP itself is NOT sent to client
    return res.status(200).json({
      ok: true,
      message: 'Code sent',
      challenge: Buffer.from(JSON.stringify({ email: normalized, expiry, sig: signature })).toString('base64url')
    });
  } catch (err) {
    console.error('Send error:', err);
    return res.status(500).json({ error: 'Failed to send email' });
  }
};
