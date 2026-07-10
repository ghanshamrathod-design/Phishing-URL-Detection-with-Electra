"use client";

import { useSession, signOut } from "next-auth/react";
import { useRouter } from "next/navigation";
import { useState, useEffect } from "react";

export default function AdminPage() {
  const { data: session, status } = useSession();
  const router = useRouter();
  const [logs, setLogs] = useState([]);
  const [loadingLogs, setLoadingLogs] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (status === "unauthenticated") {
      router.push("/login");
    }
  }, [status, router]);

  useEffect(() => {
    if (session?.user?.email === "yashhhwhat@gmail.com") {
      fetchLogs();
    }
  }, [session]);

  const fetchLogs = async () => {
    setLoadingLogs(true);
    setError(null);
    try {
      const res = await fetch(`https://phishlens-production.up.railway.app/admin/logs?email=yashhhwhat@gmail.com`);
      if (!res.ok) {
        throw new Error("Failed to fetch logs. Access Denied.");
      }
      const data = await res.json();
      setLogs(data.logs || []);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoadingLogs(false);
    }
  };

  if (status === "loading") {
    return (
      <div className="min-h-screen bg-[#0a0b0d] flex items-center justify-center">
        <p className="text-[#ede9df] text-lg animate-pulse">Loading...</p>
      </div>
    );
  }

  if (!session) return null;

  // Access Control: Block anyone who is not the admin email
  if (session.user?.email !== "yashhhwhat@gmail.com") {
    return (
      <div className="min-h-screen bg-[#0a0b0d] text-[#ede9df] flex flex-col items-center justify-center px-6 relative font-sans">
        {/* Background Grid */}
        <div className="fixed inset-0 pointer-events-none z-0" style={{ 
          backgroundImage: "linear-gradient(rgba(255,255,255,0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.03) 1px, transparent 1px)", 
          backgroundSize: "60px 60px"
        }} />
        <div className="bg-red-950/20 border border-red-500/30 rounded-3xl p-10 max-w-md text-center backdrop-blur-md relative z-10 shadow-2xl">
          <div className="w-16 h-16 bg-red-600/10 border border-red-500/40 rounded-full flex items-center justify-center mx-auto mb-6 text-red-500 text-3xl font-bold">
            ✕
          </div>
          <h1 className="text-2xl font-black mb-3 uppercase tracking-wider text-red-400">Access Denied</h1>
          <p className="text-white/60 mb-8 leading-relaxed">
            You do not have administrative privileges to view this page. Access is restricted.
          </p>
          <button
            onClick={() => router.push("/dashboard")}
            className="w-full py-3 rounded-xl bg-white/5 border border-white/10 hover:bg-white/10 text-white font-bold transition-all cursor-pointer"
          >
            Return to Dashboard
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#0a0b0d] text-[#ede9df] relative font-sans overflow-x-hidden">
      {/* Background Grid */}
      <div className="fixed inset-0 pointer-events-none z-0" style={{ 
        backgroundImage: "linear-gradient(rgba(255,255,255,0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.03) 1px, transparent 1px)", 
        backgroundSize: "60px 60px",
        maskImage: "radial-gradient(ellipse 80% 60% at 50% 30%, black 10%, transparent 70%)",
        WebkitMaskImage: "radial-gradient(ellipse 80% 60% at 50% 30%, black 10%, transparent 70%)"
      }} />

      {/* ══════ Navbar ══════ */}
      <nav className="ab-nav">
        <div className="ab-nav-inner">
          <a href="/" className="ab-logo">
            <div className="ab-logo-icon">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2L4 5v6c0 5.25 3.5 10.15 8 11.35C16.5 21.15 20 16.25 20 11V5l-8-3z"/></svg>
            </div>
            <span className="ab-logo-text">PhishLens</span>
          </a>
          <div className="ab-nav-right">
            <div className="ab-user-info hidden md:block">
              <p className="ab-user-name">{session?.user?.name}</p>
              <p className="ab-user-email">{session?.user?.email}</p>
            </div>
            <button onClick={() => signOut({ callbackUrl: "/" })} className="ab-nav-cta">
              Sign Out <span className="ab-arrow">›</span>
            </button>
          </div>
        </div>
        <div className="ab-nav-line" />
      </nav>

      {/* ══════ Main Content ══════ */}
      <main className="max-w-[1200px] mx-auto px-8 pb-16 space-y-12 relative z-10" style={{ paddingTop: "140px" }}>
        {/* Header Block */}
        <section className="flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div className="space-y-2">
            <h1 className="text-4xl md:text-5xl font-black tracking-tight text-[#ede9df]">
              Admin Activity Logs
            </h1>
            <p className="text-white/50 text-base">
              Monitor scans and security checks performed across the system.
            </p>
          </div>
          <div className="flex gap-4">
            <button
              onClick={fetchLogs}
              className="px-6 py-3 rounded-xl bg-white/5 border border-white/10 hover:bg-white/10 text-white font-bold transition-all flex items-center gap-2 cursor-pointer"
            >
              🔄 Refresh Logs
            </button>
            <button
              onClick={() => router.push("/dashboard")}
              className="px-6 py-3 rounded-xl bg-[#c6f135] text-black hover:bg-[#d4f75a] font-extrabold transition-all shadow-[0_0_20px_rgba(198,241,53,0.15)] cursor-pointer"
            >
              Dashboard
            </button>
          </div>
        </section>

        {/* Logs Table Card */}
        <section className="bg-white/5 border border-white/10 rounded-3xl p-8 backdrop-blur-md shadow-2xl">
          {loadingLogs ? (
            <div className="py-20 text-center text-white/50 animate-pulse text-lg">
              Fetching logs from system database...
            </div>
          ) : error ? (
            <div className="bg-red-950/20 border border-red-500/30 text-red-400 rounded-2xl p-6 text-center">
              <strong>Error:</strong> {error}
            </div>
          ) : logs.length === 0 ? (
            <div className="py-20 text-center text-white/40 text-lg">
              No activity logs recorded yet.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-left">
                <thead>
                  <tr className="border-b border-white/10 text-xs uppercase tracking-widest text-[#c6f135]">
                    <th className="pb-4 font-black">ID</th>
                    <th className="pb-4 font-black">User Email</th>
                    <th className="pb-4 font-black">Action Performed</th>
                    <th className="pb-4 font-black">Timestamp</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5 text-sm">
                  {logs.map((log) => (
                    <tr key={log.id} className="hover:bg-white/5 transition-colors">
                      <td className="py-4 font-bold text-white/40">#{log.id}</td>
                      <td className="py-4 font-semibold text-white/90">{log.email}</td>
                      <td className="py-4 font-medium text-white/80">
                        <span className="bg-white/5 border border-white/10 px-3 py-1 rounded-lg">
                          {log.action}
                        </span>
                      </td>
                      <td className="py-4 text-white/50 font-medium">{log.timestamp}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </main>

      {/* Navbar CSS Styles */}
      <style>{`
        .ab-nav {
          position: fixed; top: 0; left: 0; right: 0; z-index: 50;
          background: rgba(10,11,13,0.72);
          backdrop-filter: blur(20px) saturate(1.5);
          -webkit-backdrop-filter: blur(20px) saturate(1.5);
        }
        .ab-nav-inner {
          max-width: 1200px; margin: 0 auto; padding: 0 32px;
          height: 64px; display: flex; align-items: center; justify-content: space-between;
        }
        .ab-nav-line {
          height: 1px;
          background: linear-gradient(90deg, transparent, #c6f135, transparent);
          opacity: 0.25;
        }
        .ab-logo {
          display: flex; align-items: center; gap: 10px; text-decoration: none; color: #ede9df;
        }
        .ab-logo-icon {
          width: 30px; height: 30px; border-radius: 8px;
          background: #c6f135;
          color: #0a0b0d;
          display: flex; align-items: center; justify-content: center;
          box-shadow: 0 0 16px rgba(198,241,53,0.25);
        }
        .ab-logo-text {
          font-size: 17px; font-weight: 800; letter-spacing: -0.02em; color: #ede9df;
        }
        .ab-nav-right {
          display: flex; align-items: center; gap: 16px;
        }
        .ab-nav-cta {
          display: inline-flex; align-items: center; gap: 4px;
          padding: 8px 20px; border-radius: 10px;
          background: #c6f135; color: #0a0b0d;
          font-size: 14px; font-weight: 700; text-decoration: none;
          transition: all 0.2s;
          box-shadow: 0 0 20px rgba(198,241,53,0.15);
          border: none;
          cursor: pointer;
        }
        .ab-nav-cta:hover {
          background: #d4f75a;
          box-shadow: 0 0 30px rgba(198,241,53,0.25);
        }
        .ab-arrow {
          opacity: 0.6; font-size: 18px; font-weight: 900; line-height: 1; transform: translateY(-1px);
        }
        .ab-user-info {
          text-align: right;
        }
        .ab-user-name {
          font-size: 14px; font-weight: 500; color: #ede9df; margin: 0; line-height: 1.2;
        }
        .ab-user-email {
          font-size: 12px; color: rgba(255,255,255,0.5); margin: 0; line-height: 1.2; margin-top: 2px;
        }
      `}</style>
    </div>
  );
}
