export const metadata = {
  title: 'OWASP Top 10 Educational Platform',
  description:
    'Hands-on learning platform for the OWASP Top 10 across Web, API, Mobile, and LLM — lessons, cheat sheets, and locally-run vulnerable labs.',
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
