import Link from 'next/link';

export const metadata = {
  title: 'Practice Locally — OWASP Learn',
  description: 'Run the intentionally-vulnerable OWASP labs safely on your own machine with Docker or a Codespace.',
};

export default function Practice() {
  return (
    <div className="wrap">
      <div className="breadcrumb">
        <Link href="/">Home</Link>
        <span>/</span>
        <span style={{ color: 'var(--text-dim)' }}>Practice</span>
      </div>

      <section className="hero" style={{ padding: '32px 0 20px', textAlign: 'left' }}>
        <div className="eyebrow">Hands-on</div>
        <h1 style={{ fontSize: '2rem' }}>Practice locally</h1>
        <p style={{ margin: '12px 0 0', maxWidth: 660 }}>
          The lessons teach the theory; the labs let you attack real, intentionally-vulnerable apps.
          Those apps are deliberately <strong>not</strong> hosted here — a live vulnerable app is a
          liability — so you run them on your own machine, where nothing is ever exposed to the internet.
        </p>
      </section>

      <section className="section">
        <div className="mini-grid">
          <div className="mini-card">
            <h4><span className="i">▪</span> GitHub Codespaces</h4>
            <p>Nothing to install. Open the repo in a Codespace (Docker is preinstalled) and run the platform. Ports are forwarded to a private URL only you can see.</p>
            <p style={{ marginTop: 12 }}>
              <a href="https://codespaces.new/0x6a03448f4d/OWASP-TOP10" target="_blank" rel="noopener" className="btn">Open in Codespaces ↗</a>
            </p>
          </div>
          <div className="mini-card">
            <h4><span className="i">▪</span> Local Docker</h4>
            <p>With Docker installed, clone the repo and bring the platform up:</p>
            <div className="callout" style={{ marginTop: 12, borderLeft: 'none', padding: 14 }}>
              <code style={{ display: 'block', background: 'none', border: 'none', padding: 0, color: 'var(--text)', fontSize: '0.82rem', lineHeight: 1.9 }}>
                git clone https://github.com/0x6a03448f4d/OWASP-TOP10.git<br />
                cd OWASP-TOP10/platform/infra<br />
                docker compose up -d
              </code>
            </div>
          </div>
        </div>

        <div className="callout" style={{ marginTop: 22 }}>
          <h3>How it fits together</h3>
          <p>
            Read a vulnerability’s lesson here, then launch its matching lab from the local dashboard
            (<code>http://localhost</code>) to try the attack and the fix yourself. Every lab is an
            isolated Docker container you can reset or tear down at any time.
          </p>
        </div>
      </section>

      <section className="section">
        <div className="section-head"><h2>Keep learning</h2></div>
        <div className="mini-grid">
          <Link href="/learn/web" className="mini-card"><h4><span className="i">▪</span> Web Top 10</h4><p>2025 · 2021 · 2017</p></Link>
          <Link href="/learn/api" className="mini-card"><h4><span className="i">▪</span> API Top 10</h4><p>2023</p></Link>
          <Link href="/learn/mobile" className="mini-card"><h4><span className="i">▪</span> Mobile Top 10</h4><p>2024</p></Link>
          <Link href="/learn/llm" className="mini-card"><h4><span className="i">▪</span> LLM Top 10</h4><p>2025 · 2023</p></Link>
        </div>
      </section>
    </div>
  );
}
