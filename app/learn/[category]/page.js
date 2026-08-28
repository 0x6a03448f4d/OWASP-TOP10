import { notFound } from 'next/navigation';
import data from '../../data/owasp.json';
import CategoryView from './CategoryView';

export function generateStaticParams() {
  return data.categories.map((c) => ({ category: c.key }));
}

export async function generateMetadata({ params }) {
  const { category } = await params;
  const c = data.categories.find((x) => x.key === category);
  return {
    title: c ? `${c.label} Top 10 — OWASP Learn` : 'OWASP Top 10 — Learn',
    description: c ? c.blurb : undefined,
  };
}

export default async function Page({ params }) {
  const { category } = await params;
  const c = data.categories.find((x) => x.key === category);
  if (!c) notFound();
  return <CategoryView category={c} />;
}
