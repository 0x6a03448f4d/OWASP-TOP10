import Link from 'next/link';

export default function SiteHeader() {
  return (
    <header className="site-header">
      <div className="wrap">
        <Link href="/" className="brand">
          <span className="mark">◆</span>
          <span>OWASP Top 10 <span className="dim">Learn</span></span>
        </Link>
        <nav className="nav">
          <Link href="/learn/web" className="hide-sm">Web</Link>
          <Link href="/learn/api" className="hide-sm">API</Link>
          <Link href="/learn/mobile" className="hide-sm">Mobile</Link>
          <Link href="/learn/llm" className="hide-sm">LLM</Link>
          <Link href="/cheatsheets">Cheatsheets</Link>
          <Link href="/practice">Practice</Link>
          <a href="https://github.com/0x6a03448f4d/OWASP-TOP10" target="_blank" rel="noopener" className="cta">GitHub ↗</a>
        </nav>
      </div>
    </header>
  );
}
