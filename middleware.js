export const config = {
  matcher: '/((?!_vercel|favicon\\.ico).*)',
};

const realm = 'SMS Dashboard';

function unauthorized() {
  return new Response('Authentication required', {
    status: 401,
    headers: { 'WWW-Authenticate': `Basic realm="${realm}", charset="UTF-8"` },
  });
}

export default function middleware(request) {
  const expectedUser = process.env.BASIC_AUTH_USER;
  const expectedPass = process.env.BASIC_AUTH_PASS;
  if (!expectedUser || !expectedPass) return unauthorized();

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

  if (user !== expectedUser || pass !== expectedPass) return unauthorized();
}
