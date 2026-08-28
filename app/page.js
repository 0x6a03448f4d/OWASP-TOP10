// The `/` route is rewritten to the static dashboard (see next.config.mjs
// `beforeFiles`), so this component is only a graceful fallback.
export default function Home() {
  return (
    <main style={{ fontFamily: 'monospace', padding: 40, lineHeight: 1.6 }}>
      <h1>OWASP Top 10 Educational Platform</h1>
      <p>
        Loading the dashboard… if it doesn’t appear,{' '}
        <a href="/platform/frontend/index.html">enter here</a>.
      </p>
    </main>
  );
}
