"use client";

import { useState, useEffect } from "react";

export default function LoginPage() {
  const [isRegister, setIsRegister] = useState(false);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [currentUser, setCurrentUser] = useState<string | null>(null);

  useEffect(() => {
    if (typeof window !== "undefined") {
      const savedUser = localStorage.getItem("auth_username");
      if (savedUser) setCurrentUser(savedUser);
    }
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccess(null);
    setLoading(true);

    const endpoint = isRegister ? "/api/v1/auth/register" : "/api/v1/auth/login";
    const payload = isRegister
      ? { username: username.trim(), password, email: email.trim() || undefined }
      : { username: username.trim(), password };

    try {
      const res = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || "Authentication failed. Please check credentials.");
      }

      if (data.access_token) {
        localStorage.setItem("auth_token", data.access_token);
        localStorage.setItem("auth_username", data.username);
        localStorage.setItem("auth_role", data.role || "analyst");
        setCurrentUser(data.username);
        setSuccess(isRegister ? "Account created and session authenticated!" : "Logged in successfully!");
        setTimeout(() => {
          window.location.href = "/dashboard";
        }, 1000);
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Authentication error occurred.");
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem("auth_token");
    localStorage.removeItem("auth_username");
    localStorage.removeItem("auth_role");
    setCurrentUser(null);
    setSuccess("Session logged out successfully.");
  };

  return (
    <>
      <div className="page-header">
        <h2>{currentUser ? "Account Session" : isRegister ? "Create Account" : "Sign In"}</h2>
        <p>
          {currentUser
            ? `Authenticated as ${currentUser}`
            : "Sign in or register to access private investigations, memory, and analytics"}
        </p>
      </div>

      <div className="page-body">
        <div className="card" style={{ maxWidth: 480 }}>
          {currentUser ? (
            <div>
              <p style={{ marginBottom: 16 }}>
                You are currently signed in as <strong>{currentUser}</strong>.
              </p>
              <div style={{ display: "flex", gap: 12 }}>
                <a href="/dashboard" className="btn btn-primary">
                  Go to Dashboard
                </a>
                <button onClick={handleLogout} className="btn btn-secondary">
                  Sign Out
                </button>
              </div>
            </div>
          ) : (
            <>
              <div style={{ display: "flex", gap: 12, marginBottom: 20, borderBottom: "1px solid var(--border-color, #e5e7eb)", paddingBottom: 10 }}>
                <button
                  type="button"
                  onClick={() => { setIsRegister(false); setError(null); setSuccess(null); }}
                  style={{
                    background: "none",
                    border: "none",
                    fontWeight: !isRegister ? 600 : 400,
                    color: !isRegister ? "#0f766e" : "#64748b",
                    cursor: "pointer",
                    fontSize: "0.95rem",
                  }}
                >
                  Sign In
                </button>
                <button
                  type="button"
                  onClick={() => { setIsRegister(true); setError(null); setSuccess(null); }}
                  style={{
                    background: "none",
                    border: "none",
                    fontWeight: isRegister ? 600 : 400,
                    color: isRegister ? "#0f766e" : "#64748b",
                    cursor: "pointer",
                    fontSize: "0.95rem",
                  }}
                >
                  Register New User
                </button>
              </div>

              {error && (
                <div style={{ padding: "10px 14px", background: "#fef2f2", color: "#991b1b", borderRadius: 6, marginBottom: 16, fontSize: "0.875rem" }}>
                  {error}
                </div>
              )}

              {success && (
                <div style={{ padding: "10px 14px", background: "#f0fdf4", color: "#166534", borderRadius: 6, marginBottom: 16, fontSize: "0.875rem" }}>
                  {success}
                </div>
              )}

              <form onSubmit={handleSubmit}>
                <div className="form-group">
                  <label className="form-label">Username</label>
                  <input
                    className="form-input"
                    type="text"
                    required
                    placeholder="Enter username"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                  />
                </div>

                {isRegister && (
                  <div className="form-group">
                    <label className="form-label">Email Address (Optional)</label>
                    <input
                      className="form-input"
                      type="email"
                      placeholder="analyst@domain.com"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                    />
                  </div>
                )}

                <div className="form-group">
                  <label className="form-label">Password</label>
                  <input
                    className="form-input"
                    type="password"
                    required
                    placeholder={isRegister ? "At least 8 characters" : "Enter password"}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                  />
                </div>

                <button
                  type="submit"
                  className="btn btn-primary"
                  style={{ width: "100%", marginTop: 8 }}
                  disabled={loading}
                >
                  {loading ? "Processing…" : isRegister ? "Create Account" : "Sign In"}
                </button>
              </form>
            </>
          )}
        </div>
      </div>
    </>
  );
}
