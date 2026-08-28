/**
 * The discovery layer (home, category/edition browsing, cheat sheets, practice)
 * is a Next.js app under app/. The deep lesson pages and cheat sheets are
 * hand-written static HTML served from public/ (mirrored there at build time by
 * scripts/prepare-public.mjs), sharing the same amber design system.
 *
 * @type {import('next').NextConfig}
 */
const nextConfig = {
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
