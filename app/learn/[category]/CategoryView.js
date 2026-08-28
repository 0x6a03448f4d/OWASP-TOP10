'use client';
import Link from 'next/link';
import { useState } from 'react';

export default function CategoryView({ category }) {
  const editions = category.editions;
  const initial = (editions.find((e) => e.latest) || editions[0]).year;
  const [active, setActive] = useState(initial);
  const ed = editions.find((e) => e.year === active) || editions[0];
  const multi = editions.length > 1;

  return (
    <div className="wrap">
      <div className="breadcrumb">
        <Link href="/">Home</Link>
        <span>/</span>
        <span style={{ color: 'var(--text-dim)' }}>{category.label} Top 10</span>
      </div>

      <section className="section" style={{ paddingTop: 8 }}>
        <div className="section-head">
          <div>
            <div className="eyebrow">OWASP {category.label} Top 10 · {ed.year}{ed.latest ? ' (latest)' : ''}</div>
            <h2>{category.label} security risks</h2>
          </div>
        </div>
        <p style={{ color: 'var(--text-dim)', maxWidth: 640, marginBottom: 22 }}>{category.blurb}</p>

        {multi && (
          <div className="tabs" role="tablist" aria-label="Edition">
            {editions.map((e) => (
              <button
                key={e.year}
                role="tab"
                aria-selected={e.year === active}
                className={`tab${e.year === active ? ' active' : ''}`}
                onClick={() => setActive(e.year)}
              >
                {e.year}
                {e.latest && <span className="yr-latest">latest</span>}
              </button>
            ))}
          </div>
        )}

        <div className="vuln-list">
          {ed.vulns.map((v) => (
            <div key={v.id} className="vuln-row">
              <span className="vuln-rank">{v.id}</span>
              <div className="vuln-main">
                <a className="name" href={v.lessonPath}>{v.name}</a>
              </div>
              <div className="vuln-links">
                <a href={v.lessonPath}>Lesson&nbsp;→</a>
                {v.cheatPath && <a className="sheet" href={v.cheatPath}>Cheat&nbsp;sheet</a>}
              </div>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
