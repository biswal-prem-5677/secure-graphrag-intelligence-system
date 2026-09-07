"use client";

import { useState, useEffect } from "react";

export default function ProfilePage() {
  const [profile, setProfile] = useState<{
    username: string;
    role: string;
    created_at: string;
    email: string;
  } | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch("/api/v1/profile")
      .then((r) => (r.ok ? r.json() : null))
      .then((data) =>
        setProfile(
          data || {
            username: "analyst",
            role: "user",
            created_at: new Date().toISOString(),
            email: "",
          }
        )
      )
      .catch(() =>
        setProfile({
          username: "analyst",
          role: "user",
          created_at: new Date().toISOString(),
          email: "",
        })
      )
      .finally(() => setLoading(false));
  }, []);

  return (
    <>
      <div className="page-header">
        <h2>Profile</h2>
        <p>Manage your account information</p>
      </div>

      <div className="page-body">
        {loading ? (
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <span className="spinner" /> Loading…
          </div>
        ) : (
          <div className="card" style={{ maxWidth: 560 }}>
            <div className="form-group">
              <label className="form-label">Username</label>
              <input
                className="form-input"
                value={profile?.username || ""}
                readOnly
              />
            </div>
            <div className="form-group">
              <label className="form-label">Role</label>
              <div>
                <span className="tag tag-teal">{profile?.role?.toUpperCase()}</span>
              </div>
            </div>
            <div className="form-group">
              <label className="form-label">Email</label>
              <input
                className="form-input"
                placeholder="Not set"
                value={profile?.email || ""}
                readOnly
              />
            </div>
            <div className="form-group">
              <label className="form-label">Account Created</label>
              <input
                className="form-input"
                value={
                  profile?.created_at
                    ? new Date(profile.created_at).toLocaleDateString()
                    : ""
                }
                readOnly
              />
            </div>
          </div>
        )}
      </div>
    </>
  );
}
