import Link from 'next/link';
import data from '../data/owasp.json';

export const metadata = {
  title: 'Cheat Sheets — OWASP Learn',
  description: 'One-page quick references for every OWASP Top 10 vulnerability across editions.',
};

const ICONS = { web: '🌐', api: '🔌', mobile: '📱', llm: '🤖', kubernetes: '☸️', cicd: '🔄', serverless: '⚡', ml: '🧠', 'smart-contract': '📜', proactive: '🛡️' };

export default function Cheatsheets() {
  return (
    <div className="wrap">
      <div className="breadcrumb">
        <Link href="/">Home</Link>
        <span>/</span>
        <span style={{ color: 'var(--text-dim)' }}>Cheat sheets</span>
      </div>

      <section className="hero" style={{ padding: '32px 0 12px', textAlign: 'left' }}>
        <div className="eyebrow">Quick reference</div>
        <h1 style={{ fontSize: '2rem' }}>Cheat sheets</h1>
        <p style={{ margin: '12px 0 0', maxWidth: 640 }}>
          One page per vulnerability — the essence of what it is, how it’s exploited, and how to prevent it.
          Full lessons are linked from each category page.
        </p>
      </section>

      {data.categories.map((c) => {
        const withSheets = c.editions.filter((e) => e.vulns.some((v) => v.cheatPath));
        if (!withSheets.length) {
          return (
            <section key={c.key} className="section">
              <div className="section-head">
                <h2>{ICONS[c.key]} {c.label}</h2>
                <span className="sub">Cheat sheets in progress — see the <Link href={`/learn/${c.key}`} style={{ color: 'var(--accent)' }}>full lessons</Link>.</span>
              </div>
            </section>
          );
        }
        return (
          <section key={c.key} className="section">
            <div className="section-head">
              <h2>{ICONS[c.key]} {c.label}</h2>
              <Link href={`/learn/${c.key}`} className="sub" style={{ color: 'var(--accent)' }}>Full lessons →</Link>
            </div>
            {withSheets.map((e) => (
              <div key={e.year} style={{ marginBottom: 18 }}>
                <div className="eyebrow" style={{ marginBottom: 10 }}>Edition {e.year}{e.latest ? ' · latest' : ''}</div>
                <div className="vuln-list" style={{ marginTop: 0 }}>
                  {e.vulns.map((v) => (
                    <div key={v.id} className="vuln-row">
                      <span className="vuln-rank">{v.id}</span>
                      <div className="vuln-main">
                        {v.cheatPath
                          ? <a className="name" href={v.cheatPath}>{v.name}</a>
                          : <span style={{ color: 'var(--text-faint)' }}>{v.name}</span>}
                      </div>
                      <div className="vuln-links">
                        {v.cheatPath && <a href={v.cheatPath}>Open&nbsp;→</a>}
                        <a href={v.lessonPath} style={{ color: 'var(--text-faint)' }}>Lesson</a>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </section>
        );
      })}
    </div>
  );
}
