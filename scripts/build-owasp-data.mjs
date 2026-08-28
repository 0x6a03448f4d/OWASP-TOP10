/**
 * Builds the site's data model from the authoritative OWASP edition lists +
 * the actual lesson/cheatsheet files on disk, and validates every reference.
 *
 * Output: app/data/owasp.json  (consumed by the Next.js pages)
 *
 * Only editions that ACTUALLY have lesson content are included (honest nav):
 *   Web 2025/2021/2017 · API 2023 · Mobile 2024 · LLM 2025/2023
 * (year-config's API-2019 / Mobile-2016 snapshots have no content — excluded.)
 */
import { existsSync, readdirSync, writeFileSync, mkdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

// ── Authoritative edition → vulnerability lists (from platform/frontend/js/year-config.js) ──
const V = (id, number, name, slug) => ({ id, number, name, slug });

const EDITIONS = {
  web: {
    label: 'Web Application',
    blurb: 'The original OWASP Top 10 — the most critical security risks to web applications.',
    lessonDir: 'labs/web/OWASP-Web',
    editions: [
      { year: '2025', latest: true, cheatDir: 'resources/cheat-sheets/2025/web', vulns: [
        V('A01', 1, 'Broken Access Control', 'broken-access-control'),
        V('A02', 2, 'Security Misconfiguration', 'security-misconfiguration'),
        V('A03', 3, 'Software Supply Chain Failures', 'software-supply-chain-failures'),
        V('A04', 4, 'Cryptographic Failures', 'cryptographic-failures'),
        V('A05', 5, 'Injection', 'injection'),
        V('A06', 6, 'Insecure Design', 'insecure-design'),
        V('A07', 7, 'Authentication Failures', 'authentication-failures'),
        V('A08', 8, 'Software or Data Integrity Failures', 'software-data-integrity-failures'),
        V('A09', 9, 'Logging & Alerting Failures', 'logging-alerting-failures'),
        V('A10', 10, 'Mishandling of Exceptional Conditions', 'mishandling-exceptional-conditions'),
      ]},
      { year: '2021', cheatDir: 'resources/cheat-sheets/web', vulns: [
        V('A01', 1, 'Broken Access Control', 'broken-access-control'),
        V('A02', 2, 'Cryptographic Failures', 'cryptographic-failures'),
        V('A03', 3, 'Injection', 'injection'),
        V('A04', 4, 'Insecure Design', 'insecure-design'),
        V('A05', 5, 'Security Misconfiguration', 'security-misconfiguration'),
        V('A06', 6, 'Vulnerable and Outdated Components', 'vulnerable-outdated-components'),
        V('A07', 7, 'Identification and Authentication Failures', 'identification-authentication-failures'),
        V('A08', 8, 'Software and Data Integrity Failures', 'software-data-integrity-failures'),
        V('A09', 9, 'Security Logging and Monitoring Failures', 'security-logging-monitoring-failures'),
        V('A10', 10, 'Server-Side Request Forgery (SSRF)', 'server-side-request-forgery'),
      ]},
      { year: '2017', cheatDir: 'resources/cheat-sheets/2017/web', vulns: [
        V('A1', 1, 'Injection', 'injection'),
        V('A2', 2, 'Broken Authentication', 'broken-authentication'),
        V('A3', 3, 'Sensitive Data Exposure', 'sensitive-data-exposure'),
        V('A4', 4, 'XML External Entities (XXE)', 'xml-external-entities'),
        V('A5', 5, 'Broken Access Control', 'broken-access-control'),
        V('A6', 6, 'Security Misconfiguration', 'security-misconfiguration'),
        V('A7', 7, 'Cross-Site Scripting (XSS)', 'cross-site-scripting'),
        V('A8', 8, 'Insecure Deserialization', 'insecure-deserialization'),
        V('A9', 9, 'Vulnerable and Outdated Components', 'vulnerable-outdated-components'),
        V('A10', 10, 'Insufficient Logging & Monitoring', 'insufficient-logging-monitoring'),
      ]},
    ],
  },
  api: {
    label: 'API Security',
    blurb: 'Risks specific to APIs — object/function authorization, resource consumption, and more.',
    lessonDir: 'labs/api/OWASP-API',
    editions: [
      { year: '2023', latest: true, cheatDir: 'resources/cheat-sheets/api', vulns: [
        V('API01', 1, 'Broken Object Level Authorization', 'broken-object-level-authorization'),
        V('API02', 2, 'Broken Authentication', 'broken-authentication'),
        V('API03', 3, 'Broken Object Property Level Authorization', 'broken-object-property-level-authorization'),
        V('API04', 4, 'Unrestricted Resource Consumption', 'unrestricted-resource-consumption'),
        V('API05', 5, 'Broken Function Level Authorization', 'broken-function-level-authorization'),
        V('API06', 6, 'Unrestricted Access to Sensitive Business Flows', 'unrestricted-access-to-sensitive-business-flows'),
        V('API07', 7, 'Server-Side Request Forgery (SSRF)', 'server-side-request-forgery'),
        V('API08', 8, 'Security Misconfiguration', 'security-misconfiguration'),
        V('API09', 9, 'Improper Inventory Management', 'improper-inventory-management'),
        V('API10', 10, 'Unsafe Consumption of APIs', 'unsafe-consumption-of-apis'),
      ]},
    ],
  },
  mobile: {
    label: 'Mobile',
    blurb: 'The OWASP Mobile Top 10 (2024) — the top risks for mobile applications.',
    lessonDir: 'labs/mobile/OWASP-Mobile',
    editions: [
      { year: '2024', latest: true, cheatDir: 'resources/cheat-sheets/mobile', vulns: [
        V('M01', 1, 'Improper Credential Usage', 'improper-credential-usage'),
        V('M02', 2, 'Inadequate Supply Chain Security', 'inadequate-supply-chain-security'),
        V('M03', 3, 'Insecure Authentication/Authorization', 'insecure-authentication-authorization'),
        V('M04', 4, 'Insufficient Input/Output Validation', 'insufficient-input-output-validation'),
        V('M05', 5, 'Insecure Communication', 'insecure-communication'),
        V('M06', 6, 'Inadequate Privacy Controls', 'inadequate-privacy-controls'),
        V('M07', 7, 'Insufficient Binary Protections', 'insufficient-binary-protections'),
        V('M08', 8, 'Security Misconfiguration', 'security-misconfiguration'),
        V('M09', 9, 'Insecure Data Storage', 'insecure-data-storage'),
        V('M10', 10, 'Insufficient Cryptography', 'insufficient-cryptography'),
      ]},
    ],
  },
  llm: {
    label: 'LLM & GenAI',
    blurb: 'The OWASP Top 10 for Large Language Model applications — prompt injection, agents, RAG, and more.',
    lessonDir: 'labs/llm/OWASP-LLM',
    editions: [
      { year: '2025', latest: true, cheatDir: 'resources/cheat-sheets/2025/llm', vulns: [
        V('LLM01', 1, 'Prompt Injection', 'prompt-injection'),
        V('LLM02', 2, 'Sensitive Information Disclosure', 'sensitive-information-disclosure'),
        V('LLM03', 3, 'Supply Chain', 'supply-chain-vulnerabilities'),
        V('LLM04', 4, 'Data and Model Poisoning', 'data-model-poisoning'),
        V('LLM05', 5, 'Improper Output Handling', 'improper-output-handling'),
        V('LLM06', 6, 'Excessive Agency', 'excessive-agency'),
        V('LLM07', 7, 'System Prompt Leakage', 'system-prompt-leakage'),
        V('LLM08', 8, 'Vector and Embedding Weaknesses', 'vector-embedding-weaknesses'),
        V('LLM09', 9, 'Misinformation', 'misinformation'),
        V('LLM10', 10, 'Unbounded Consumption', 'unbounded-consumption'),
      ]},
      { year: '2023', cheatDir: 'resources/cheat-sheets/llm', vulns: [
        V('LLM01', 1, 'Prompt Injection', 'prompt-injection'),
        V('LLM02', 2, 'Insecure Output Handling', 'insecure-output-handling'),
        V('LLM03', 3, 'Training Data Poisoning', 'training-data-poisoning'),
        V('LLM04', 4, 'Model Denial of Service', 'model-denial-of-service'),
        V('LLM05', 5, 'Supply Chain Vulnerabilities', 'supply-chain-vulnerabilities'),
        V('LLM06', 6, 'Sensitive Information Disclosure', 'sensitive-information-disclosure'),
        V('LLM07', 7, 'Insecure Plugin Design', 'insecure-plugin-design'),
        V('LLM08', 8, 'Excessive Agency', 'excessive-agency'),
        V('LLM09', 9, 'Overreliance', 'overreliance'),
        V('LLM10', 10, 'Model Theft', 'model-theft'),
      ]},
    ],
  },
};

// Pull an accurate 1-paragraph summary from a lesson's overview.md ("What is …?").
function extractSummary(mdAbsPath) {
  if (!existsSync(mdAbsPath)) return null;
  const lines = readFileSync(mdAbsPath, 'utf8').split('\n');
  let i = lines.findIndex((l) => /^##\s+What\s+(is|are)\b/i.test(l));
  if (i === -1) i = lines.findIndex((l, n) => n > 0 && /^##\s+\S/.test(l) && !/table of contents/i.test(l));
  if (i === -1) return null;
  const para = [];
  for (let j = i + 1; j < lines.length; j++) {
    const l = lines[j].trim();
    if (/^##\s/.test(l)) break; // reached the next top-level section
    if (!para.length) {
      // Skip blanks, rules, sub-headings (### …) and list/table lines before the intro paragraph.
      if (l === '' || l === '---' || l.startsWith('#') || l.startsWith('```') ||
          l.startsWith('|') || l.startsWith('- ') || /^\d+\.\s/.test(l)) continue;
    } else if (l === '' || l.startsWith('#') || l.startsWith('```')) {
      break; // paragraph ended
    }
    if (l) para.push(l);
  }
  if (!para.length) return null;
  let s = para.join(' ')
    .replace(/\[([^\]]+)\]\([^)]+\)/g, '$1') // links -> text
    .replace(/\*\*/g, '').replace(/\*/g, '').replace(/`/g, '')
    .replace(/\s+/g, ' ').trim();
  // Keep it to the first couple of sentences for a tidy accordion.
  const sentences = s.match(/[^.!?]+[.!?]+/g);
  if (sentences && sentences.length > 2) s = sentences.slice(0, 2).join(' ').trim();
  return s;
}

// Build a slug -> lesson-folder lookup per category by scanning the lesson dir.
function folderIndex(lessonDir) {
  const abs = join(root, lessonDir);
  if (!existsSync(abs)) return {};
  const idx = {};
  for (const d of readdirSync(abs, { withFileTypes: true })) {
    if (!d.isDirectory()) continue;
    // Strip a leading id like "01-", "API01-", "M01-", "LLM01-" then kebab-lower it.
    const norm = d.name.replace(/^[A-Za-z]*\d+-/, '').toLowerCase();
    idx[norm] = d.name;
  }
  return idx;
}

const problems = [];
const out = { categories: [] };

for (const [key, cat] of Object.entries(EDITIONS)) {
  const idx = folderIndex(cat.lessonDir);
  const catOut = { key, label: cat.label, blurb: cat.blurb, editions: [] };
  for (const ed of cat.editions) {
    const edOut = { year: ed.year, latest: !!ed.latest, vulns: [] };
    for (const v of ed.vulns) {
      const folder = idx[v.slug];
      let lessonPath = null, cheatPath = null, summary = null;
      if (folder) {
        const lp = `${cat.lessonDir}/${folder}/overview.html`;
        if (existsSync(join(root, lp))) lessonPath = '/' + lp;
        else problems.push(`MISSING lesson overview: ${lp} (${key} ${ed.year} ${v.id})`);
        summary = extractSummary(join(root, cat.lessonDir, folder, 'overview.md'));
        if (!summary) problems.push(`NO summary extracted: ${cat.lessonDir}/${folder}/overview.md`);
      } else {
        problems.push(`NO folder for slug "${v.slug}" in ${cat.lessonDir} (${key} ${ed.year} ${v.id})`);
      }
      // Cheatsheet file naming: web = NN-slug.html, api = apiNN-slug.html, mobile = mNN-slug.html, llm = llmNN-slug.html
      // A few files use a legacy name; alias those to the canonical slug.
      const CHEAT_ALIAS = { 'vulnerable-outdated-components': 'using-components-with-known-vulnerabilities' };
      if (ed.cheatDir) {
        const num2 = String(v.number).padStart(2, '0');
        const prefix = key === 'web' ? num2 : key === 'api' ? `api${num2}` : key === 'mobile' ? `m${num2}` : `llm${num2}`;
        for (const fileSlug of [v.slug, CHEAT_ALIAS[v.slug]].filter(Boolean)) {
          const cp = `${ed.cheatDir}/${prefix}-${fileSlug}.html`;
          if (existsSync(join(root, cp))) { cheatPath = '/' + cp; break; }
        }
      }
      // cheatsheet is optional; note if absent
      edOut.vulns.push({ ...v, lessonPath, cheatPath, summary });
    }
    catOut.editions.push(edOut);
  }
  out.categories.push(catOut);
}

const outDir = join(root, 'app', 'data');
mkdirSync(outDir, { recursive: true });
writeFileSync(join(outDir, 'owasp.json'), JSON.stringify(out, null, 2));

// Report
let lessons = 0, cheats = 0, total = 0;
for (const c of out.categories) for (const e of c.editions) for (const v of e.vulns) {
  total++; if (v.lessonPath) lessons++; if (v.cheatPath) cheats++;
}
console.log(`Built app/data/owasp.json`);
console.log(`  ${out.categories.length} categories, ${total} vuln entries`);
console.log(`  lessons resolved: ${lessons}/${total}   cheatsheets resolved: ${cheats}/${total}`);
if (problems.length) {
  console.log(`\n  ${problems.length} PROBLEM(S):`);
  for (const p of problems) console.log('   - ' + p);
} else {
  console.log('  ✓ every lesson reference resolves');
}
