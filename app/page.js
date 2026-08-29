import Link from 'next/link';
import data from './data/owasp.json';

const ICONS = { web: '🌐', api: '🔌', mobile: '📱', llm: '🤖', kubernetes: '☸️', cicd: '🔄', serverless: '⚡', ml: '🧠', 'smart-contract': '📜', proactive: '🛡️' };

export default function Home() {
  return (
    <>
      <section className="hero wrap">
        <h1>Learn the <span className="accent">OWASP Top 10</span></h1>
        <p>
          Clear, practical lessons on the most critical security risks — across ten OWASP projects:
          Web, API, Mobile, LLM, Kubernetes, CI/CD, ML, Smart Contracts, and Serverless, plus the
          Proactive Controls to defend against them. Every edition, easy to navigate.
        </p>
        <div className="hero-actions">
          <Link href="/learn/web" className="btn primary">Start with Web →</Link>
          <Link href="/cheatsheets" className="btn">Browse cheat sheets</Link>
        </div>
      </section>

      <section className="section wrap">
        <div className="section-head">
          <h2>Choose a category</h2>
          <span className="sub">Pick an area, then an edition — the most recent is selected by default.</span>
        </div>
        <div className="cat-grid">
          {data.categories.map((c) => {
            const latest = c.editions.find((e) => e.latest) || c.editions[0];
            return (
              <Link key={c.key} href={`/learn/${c.key}`} className="cat-card">
                <div className="icon">{ICONS[c.key]}</div>
                <h3>{c.label} Top 10</h3>
                <p>{c.blurb}</p>
                <div className="editions">
                  {c.editions.map((e) => (
                    <span key={e.year} className={`pill${e.latest ? ' latest' : ''}`}>{e.year}</span>
                  ))}
                </div>
              </Link>
            );
          })}
        </div>
      </section>

      <section className="section wrap">
        <div className="mini-grid">
          <Link href="/cheatsheets" className="mini-card">
            <h4><span className="i">▪</span> Cheat sheets</h4>
            <p>Quick, one-page references for every vulnerability — what it is, how it’s attacked, and how to prevent it.</p>
          </Link>
          <Link href="/practice" className="mini-card">
            <h4><span className="i">▪</span> Practice locally</h4>
            <p>Hands-on vulnerable labs you run on your own machine with Docker or a Codespace — never exposed online.</p>
          </Link>
          <a href="https://owasp.org/www-project-top-ten/" target="_blank" rel="noopener" className="mini-card">
            <h4><span className="i">▪</span> Official OWASP ↗</h4>
            <p>The canonical OWASP Top 10 projects and documentation on owasp.org.</p>
          </a>
        </div>
      </section>
    </>
  );
}
