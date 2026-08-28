export default function SiteFooter() {
  return (
    <footer className="site-footer">
      <div className="wrap">
        <span>An open educational resource on the OWASP Top 10 — for learning and defense, never exploitation.</span>
        <span>
          <a href="https://owasp.org/" target="_blank" rel="noopener">OWASP.org</a>
          {' · '}
          <a href="https://github.com/0x6a03448f4d/OWASP-TOP10" target="_blank" rel="noopener">Source</a>
          {' · MIT'}
        </span>
      </div>
    </footer>
  );
}
