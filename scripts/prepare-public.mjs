/**
 * Copies the static learning-site content into `public/` so Next.js serves it.
 *
 * The site's internal links are root-relative (e.g. /platform/frontend/js/...,
 * /labs/..., /resources/...). Mirroring these directories under public/ keeps
 * every link working while leaving the originals in place for the local Docker
 * lab flow (docker-compose + the Flask lab-manager scan the repo-root paths).
 *
 * The Docker lab source dirs (each lesson's `lab/` subfolder) are NOT served on
 * the hosted site by design (labs run locally), so they're excluded to keep the
 * deployment lean; `node_modules`/VCS dirs are excluded too.
 */
import { cpSync, existsSync, mkdirSync, rmSync } from 'node:fs';
import { dirname, join, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const pub = join(root, 'public');

// URL-root directories/files that make up the served static site.
const items = [
  'platform/frontend',
  'labs',
  'resources',
  'gamification',
  'images',
  'README.md',
];

const EXCLUDE = /(^|[\\/])(node_modules|\.git)([\\/]|$)/;
// A lesson's Docker lab lives in a `lab/` dir — not served on the hosted site.
const isDockerLabDir = (p) => `${sep}lab${sep}`.length && p.split(sep).includes('lab');

// Start clean so removed source files don't linger in a cached public/.
if (existsSync(pub)) rmSync(pub, { recursive: true, force: true });
mkdirSync(pub, { recursive: true });

let copied = 0;
for (const rel of items) {
  const src = join(root, rel);
  if (!existsSync(src)) continue;
  const dest = join(pub, rel);
  mkdirSync(dirname(dest), { recursive: true });
  cpSync(src, dest, {
    recursive: true,
    filter: (s) => !EXCLUDE.test(s) && !isDockerLabDir(s),
  });
  copied++;
}

console.log(`prepare-public: mirrored ${copied} item(s) into public/`);
