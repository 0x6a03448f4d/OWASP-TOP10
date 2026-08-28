import './globals.css';
import SiteHeader from './components/SiteHeader';
import SiteFooter from './components/SiteFooter';

export const metadata = {
  title: 'OWASP Top 10 — Learn',
  description:
    'Learn the OWASP Top 10 across Web, API, Mobile, and LLM — every edition, with clear lessons, cheat sheets, and code examples. Easy to navigate, focused on the latest editions.',
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>
        <SiteHeader />
        <main>{children}</main>
        <SiteFooter />
      </body>
    </html>
  );
}
