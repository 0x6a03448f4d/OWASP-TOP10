/**
 * The discovery layer (home, category/edition browsing, cheat sheets, practice)
 * is a Next.js app under app/. The deep lesson pages and cheat sheets are
 * hand-written static HTML served from public/ (mirrored there at build time by
 * scripts/prepare-public.mjs), sharing the same amber design system.
 *
 * @type {import('next').NextConfig}
 */
// The static lesson pages use inline <style>/<script> and load syntax
// highlighting from cdnjs, so the CSP allowlists that one CDN plus inline while
// still blocking every other origin, plugins and framing. Nonces aren't
// feasible here (hand-written static HTML), so 'unsafe-inline' is a deliberate,
// scoped trade-off for a content site with no user input.
const csp = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com",
  "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com",
  "font-src 'self' https://cdnjs.cloudflare.com data:",
  "img-src 'self' data:",
  "object-src 'none'",
  "base-uri 'self'",
  "frame-ancestors 'none'",
  "upgrade-insecure-requests",
].join("; ");

const nextConfig = {
  // Don't advertise the framework (removes the X-Powered-By header).
  poweredByHeader: false,
  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          { key: 'Content-Security-Policy', value: csp },
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
          { key: 'Permissions-Policy', value: 'geolocation=(), microphone=(), camera=()' },
          { key: 'Cross-Origin-Opener-Policy', value: 'same-origin' },
          { key: 'Cross-Origin-Resource-Policy', value: 'same-origin' },
          { key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains; preload' },
        ],
      },
    ];
  },
};

export default nextConfig;
