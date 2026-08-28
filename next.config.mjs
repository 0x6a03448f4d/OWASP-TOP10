/**
 * The learning site is a large set of hand-written static HTML pages that live
 * at their existing repo paths (so the local Docker lab-manager keeps working).
 * `scripts/prepare-public.mjs` copies the served content into `public/` at build
 * time; Next.js then serves it, with `/` and `/labs` rewritten to the real files.
 *
 * @type {import('next').NextConfig}
 */
const nextConfig = {
  async rewrites() {
    return {
      beforeFiles: [
        { source: '/', destination: '/platform/frontend/index.html' },
        { source: '/labs', destination: '/platform/frontend/owasp-labs.html' },
      ],
    };
  },
  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
          { key: 'Permissions-Policy', value: 'geolocation=(), microphone=(), camera=()' },
        ],
      },
    ];
  },
};

export default nextConfig;
