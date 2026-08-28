'use client';
import Link from 'next/link';
import { useMemo, useState } from 'react';

export default function CategoryView({ category }) {
  const editions = category.editions;
  const initial = (editions.find((e) => e.latest) || editions[0]).year;
  const [active, setActive] = useState(initial);
  const [open, setOpen] = useState(() => new Set());
  const ed = editions.find((e) => e.year === active) || editions[0];
  const multi = editions.length > 1;

  const allOpen = useMemo(() => ed.vulns.every((v) => open.has(v.id)), [ed, open]);

  function toggle(id) {
    setOpen((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  }
  function switchEdition(year) {
    setActive(year);
    setOpen(new Set());
  }
  function toggleAll() {
    setOpen(allOpen ? new Set() : new Set(ed.vulns.map((v) => v.id)));
  }

  return (
    <div className="wrap">
      <div className="breadcrumb">
        <Link href="/">Home</Link>
        <span>/</span>
        <span style={{ color: 'var(--text-dim)' }}>{category.label} Top 10</span>
      </div>

      <section className="section" style={{ paddingTop: 8 }}>
        <div className="eyebrow">OWASP {category.label} Top 10 · {ed.year}{ed.latest ? ' (latest)' : ''}</div>
        <h2 style={{ fontSize: '1.9rem', letterSpacing: '-0.01em', margin: '4px 0 10px' }}>
          {category.label} security risks
        </h2>
        <p style={{ color: 'var(--text-dim)', maxWidth: 640, marginBottom: 22 }}>{category.blurb}</p>

        <div className="edition-bar">
          {multi ? (
            <div className="tabs" role="tablist" aria-label="Edition">
              {editions.map((e) => (
                <button
                  key={e.year}
                  role="tab"
                  aria-selected={e.year === active}
                  className={`tab${e.year === active ? ' active' : ''}`}
                  onClick={() => switchEdition(e.year)}
                >
                  {e.year}
                  {e.latest && <span className="yr-latest">latest</span>}
                </button>
              ))}
            </div>
          ) : <span />}
          <button className="link-btn" onClick={toggleAll}>
            {allOpen ? 'Collapse all' : 'Expand all'}
          </button>
        </div>

        <div className="acc-list">
          {ed.vulns.map((v) => {
            const isOpen = open.has(v.id);
            return (
              <div key={v.id} className={`acc${isOpen ? ' open' : ''}`}>
                <button className="acc-head" onClick={() => toggle(v.id)} aria-expanded={isOpen}>
                  <span className="vuln-rank">{v.id}</span>
                  <span className="acc-name">{v.name}</span>
                  <span className="acc-chevron" aria-hidden>▾</span>
                </button>
                <div className="acc-body-wrap">
                  <div className="acc-body">
                    {v.summary && <p>{v.summary}</p>}
                    <div className="acc-links">
                      <a className="btn primary" href={v.lessonPath}>Full lesson →</a>
                      {v.cheatPath && <a className="btn" href={v.cheatPath}>Cheat sheet</a>}
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </section>
    </div>
  );
}
