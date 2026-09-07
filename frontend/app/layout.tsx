import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Secure GraphRAG — Knowledge Intelligence System",
  description:
    "Production-grade GraphRAG cybersecurity threat-intelligence investigation platform with grounded reasoning, multi-hop traversal, and explainable confidence scoring.",
};

const NAV = [
  { section: "Investigation" },
  { href: "/dashboard", label: "Query Console", icon: "🔍" },
  { href: "/billing", label: "Usage & Billing", icon: "📊" },
  { section: "Account" },
  { href: "/login", label: "Sign In / Register", icon: "🔐" },
  { href: "/profile", label: "Profile", icon: "👤" },
  { href: "/settings", label: "Settings", icon: "⚙️" },
  { section: "Admin" },
  { href: "/admin/observability", label: "Observability", icon: "📈" },
  { href: "/admin/quality", label: "AI Quality", icon: "🧪" },
  { section: "Information" },
  { href: "/about", label: "About", icon: "ℹ️" },
  { href: "/trust", label: "Trust & Security", icon: "🛡️" },
  { href: "/contact", label: "Contact", icon: "✉️" },
  { href: "/privacy", label: "Privacy Policy", icon: "📄" },
  { href: "/terms", label: "Terms of Service", icon: "📋" },
];

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>
        <div className="app-layout">
          <aside className="sidebar">
            <div className="sidebar-brand">
              <h1>Secure GraphRAG</h1>
              <span>Knowledge Intelligence System</span>
            </div>
            <nav className="sidebar-nav">
              {NAV.map((item, i) =>
                "section" in item ? (
                  <div key={i} className="sidebar-section-title">
                    {item.section}
                  </div>
                ) : (
                  <a key={i} href={item.href} className="sidebar-link">
                    <span className="icon">{item.icon}</span>
                    {item.label}
                  </a>
                )
              )}
            </nav>
            <div className="sidebar-footer">
              v1.0.0 &middot; GraphRAG Intelligence
            </div>
          </aside>
          <main className="main-content">{children}</main>
        </div>
      </body>
    </html>
  );
}
