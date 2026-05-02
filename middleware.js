export const config = {
  matcher: '/((?!_vercel|favicon\\.ico).*)',
};

const realm = 'SMS Dashboard';

// Security headers re-applied on the 401 challenge so the WWW-Authenticate
// page itself ships with strict CSP. Headers for the authenticated 200 are
// served by vercel.json.
const SECURITY_HEADERS = {
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
};

function unauthorized() {
  return new Response('Authentication required', {
    status: 401,
    headers: {
      'WWW-Authenticate': `Basic realm="${realm}", charset="UTF-8"`,
      ...SECURITY_HEADERS,
    },
  });
}

// Constant-time string comparison to avoid timing leaks on credentials.
function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export default function middleware(request) {
  const expectedUser = process.env.BASIC_AUTH_USER;
  const expectedPass = process.env.BASIC_AUTH_PASS;
  if (!expectedUser || !expectedPass) {
    console.error('[middleware] BASIC_AUTH_USER or BASIC_AUTH_PASS not set; refusing all traffic');
    return unauthorized();
  }

  const auth = request.headers.get('authorization');
  if (!auth || !auth.toLowerCase().startsWith('basic ')) return unauthorized();

  let decoded;
  try {
    decoded = atob(auth.slice(6).trim());
  } catch {
    return unauthorized();
  }

  const idx = decoded.indexOf(':');
  if (idx < 0) return unauthorized();

  const user = decoded.slice(0, idx);
  const pass = decoded.slice(idx + 1);

  // Compare both fields to keep total work constant regardless of which side is wrong.
  const userOk = timingSafeEqual(user, expectedUser);
  const passOk = timingSafeEqual(pass, expectedPass);
  if (!(userOk && passOk)) return unauthorized();
}
