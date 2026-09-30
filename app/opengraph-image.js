import { ImageResponse } from "next/og";

export const size = { width: 1200, height: 630 };
export const contentType = "image/png";
export const alt = "OWASP Top 10 - Learn";

export default function OG() {
  return new ImageResponse(
    (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          flexDirection: "column",
          justifyContent: "center",
          padding: "80px",
          background: "linear-gradient(135deg, #0f0d09 0%, #1a1408 100%)",
          color: "#f5ecd8",
          fontFamily: "sans-serif",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 24 }}>
          <div style={{ width: 60, height: 60, borderRadius: 14, background: "linear-gradient(135deg,#f59e0b,#fbbf24)" }} />
          <div style={{ fontSize: 62, fontWeight: 800, letterSpacing: -1 }}>OWASP Top 10</div>
        </div>
        <div style={{ marginTop: 34, fontSize: 38, color: "#c9bb9c", maxWidth: 940, lineHeight: 1.3 }}>
          Learn the top Web, API, Mobile, LLM, Kubernetes, CI/CD and more security risks - with labs, cheat sheets and practice.
        </div>
        <div style={{ marginTop: 46, fontSize: 26, color: "#8a7d63" }}>owasp.0x6a03448f4d.com</div>
      </div>
    ),
    size
  );
}
