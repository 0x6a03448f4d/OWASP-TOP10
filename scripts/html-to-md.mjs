/**
 * Backfill a lesson .md mirror from its .html (the .content block).
 * Usage: node scripts/html-to-md.mjs <file1.html> <file2.html> ...
 * Writes <file>.md next to each. Handles the tags our lessons use.
 */
import { readFileSync, writeFileSync } from 'node:fs';

function decode(s) {
  return s.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'").replace(/&mdash;/g, '—').replace(/&ndash;/g, '–')
    .replace(/&larr;/g, '←').replace(/&rarr;/g, '→').replace(/&hellip;/g, '…')
    .replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&');
}
const strip = (s) => decode(s.replace(/<[^>]+>/g, '')).replace(/\s+/g, ' ').trim();

function inline(s) {
  return decode(
    s.replace(/<\s*br\s*\/?>/gi, '  \n')
     .replace(/<(strong|b)>([\s\S]*?)<\/\1>/gi, (_, __, t) => `**${strip(t)}**`)
     .replace(/<(em|i)>([\s\S]*?)<\/\1>/gi, (_, __, t) => `*${strip(t)}*`)
     .replace(/<code>([\s\S]*?)<\/code>/gi, (_, t) => '`' + decode(t.replace(/<[^>]+>/g, '')) + '`')
     .replace(/<a[^>]*href="([^"]*)"[^>]*>([\s\S]*?)<\/a>/gi, (_, h, t) => `[${strip(t)}](${h})`)
     .replace(/<[^>]+>/g, '')
  ).replace(/[ \t]+/g, ' ').trim();
}

function convert(html) {
  // Isolate the main content block.
  let m = html.match(/<div class="content"[^>]*>([\s\S]*?)<\/div>\s*(?:<\/div>\s*)*<\/body>/i);
  let body = m ? m[1] : (html.match(/<body[^>]*>([\s\S]*?)<\/body>/i)?.[1] ?? html);
  // Drop the back-nav and any <style>/<script>.
  body = body.replace(/<style[\s\S]*?<\/style>/gi, '').replace(/<script[\s\S]*?<\/script>/gi, '')
             .replace(/<a[^>]*class="back-nav"[\s\S]*?<\/a>/gi, '');
  const out = [];
  const tokens = body.split(/(?=<(?:h[1-6]|p|ul|ol|pre|table|blockquote|div)[ >])/i);
  for (let chunk of tokens) {
    const h = chunk.match(/^<h([1-6])[^>]*>([\s\S]*?)<\/h\1>/i);
    if (h) { out.push('#'.repeat(+h[1]) + ' ' + strip(h[2]), ''); continue; }
    const pre = chunk.match(/^<pre[^>]*>([\s\S]*?)<\/pre>/i);
    if (pre) {
      const code = decode(pre[1].replace(/<\/?code[^>]*>/gi, '').replace(/<[^>]+>/g, ''));
      out.push('```', code.replace(/^\n+|\n+$/g, ''), '```', ''); continue;
    }
    const p = chunk.match(/^<p[^>]*>([\s\S]*?)<\/p>/i);
    if (p) { const t = inline(p[1]); if (t) out.push(t, ''); continue; }
    const bq = chunk.match(/^<blockquote[^>]*>([\s\S]*?)<\/blockquote>/i);
    if (bq) { out.push('> ' + inline(bq[1]).replace(/\n/g, '\n> '), ''); continue; }
    const list = chunk.match(/^<(ul|ol)[^>]*>([\s\S]*?)<\/\1>/i);
    if (list) {
      const ordered = list[1].toLowerCase() === 'ol';
      const items = [...list[2].matchAll(/<li[^>]*>([\s\S]*?)<\/li>/gi)];
      items.forEach((it, i) => out.push((ordered ? `${i + 1}. ` : '- ') + inline(it[1])));
      out.push(''); continue;
    }
    const table = chunk.match(/^<table[^>]*>([\s\S]*?)<\/table>/i);
    if (table) {
      const rows = [...table[1].matchAll(/<tr[^>]*>([\s\S]*?)<\/tr>/gi)];
      rows.forEach((r, ri) => {
        const cells = [...r[1].matchAll(/<t[hd][^>]*>([\s\S]*?)<\/t[hd]>/gi)].map((c) => inline(c[1]));
        if (!cells.length) return;
        out.push('| ' + cells.join(' | ') + ' |');
        if (ri === 0) out.push('| ' + cells.map(() => '---').join(' | ') + ' |');
      });
      out.push(''); continue;
    }
  }
  return out.join('\n').replace(/\n{3,}/g, '\n\n').trim() + '\n';
}

for (const f of process.argv.slice(2)) {
  const md = convert(readFileSync(f, 'utf8'));
  const out = f.replace(/\.html$/, '.md');
  writeFileSync(out, md);
  console.log(`wrote ${out} (${md.length} bytes)`);
}
