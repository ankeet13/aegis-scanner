// Author: Aayush — React Dashboard

import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend,
} from 'recharts';

/* ========================================================================
   AEGIS Scanner — React Dashboard
   Complete single-file app with all components.
   ======================================================================== */

const API_BASE = process.env.REACT_APP_API_URL || 'http://localhost:5000';

/* ---------- colour constants ---------- */
const SEVERITY_COLORS = {
  Critical: '#dc2626',
  High: '#ea580c',
  Medium: '#ca8a04',
  Low: '#2563eb',
  Info: '#6b7280',
};

const RISK_COLORS = {
  Safe: '#16a34a',
  Low: '#2563eb',
  Medium: '#ca8a04',
  High: '#ea580c',
  Critical: '#dc2626',
};

const OWASP_COLORS = {
  'A01:2021': '#ea580c',
  'A03:2021': '#dc2626',
  'A05:2021': '#2563eb',
  'A07:2021': '#ca8a04',
};

/* =======================================================================
   MAIN APP
   ======================================================================= */
export default function App() {
  const [phase, setPhase] = useState('input'); // input | scanning | results
  const [targetUrl, setTargetUrl] = useState('');
  const [authCookie, setAuthCookie] = useState('');
  const [scanResults, setScanResults] = useState(null);
  const [error, setError] = useState(null);
  const [progress, setProgress] = useState({ message: 'Initialising...', pct: 0 });

  const startScan = async () => {
    if (!targetUrl.trim()) return;

    setPhase('scanning');
    setError(null);
    setProgress({ message: 'Connecting to target...', pct: 5 });

    const phases = [
      { msg: 'Crawling target application...', pct: 15 },
      { msg: 'Discovering endpoints and forms...', pct: 25 },
      { msg: 'Running SQL Injection scanner...', pct: 40 },
      { msg: 'Running Broken Access Control scanner...', pct: 55 },
      { msg: 'Running Authentication scanner...', pct: 65 },
      { msg: 'Running Misconfiguration scanner...', pct: 75 },
      { msg: 'ML model predicting risk level...', pct: 85 },
      { msg: 'Generating recommendations...', pct: 90 },
      { msg: 'Building report...', pct: 95 },
    ];

    // Simulate progress while waiting for the API
    let idx = 0;
    const interval = setInterval(() => {
      if (idx < phases.length) {
        setProgress(phases[idx]);
        idx++;
      }
    }, 2500);

    try {
      let cookieObj = null;
      if (authCookie.trim()) {
        try {
          cookieObj = JSON.parse(authCookie);
        } catch {
          cookieObj = null;
        }
      }

      const resp = await axios.post(`${API_BASE}/api/scan`, {
        target_url: targetUrl.trim(),
        auth_cookie: cookieObj,
        generate_report: true,
      });

      clearInterval(interval);
      setProgress({ message: 'Scan complete!', pct: 100 });

      setTimeout(() => {
        setScanResults(resp.data);
        setPhase('results');
      }, 600);
    } catch (err) {
      clearInterval(interval);
      setError(err.response?.data?.message || err.message || 'Scan failed');
      setPhase('input');
    }
  };

  const resetScan = () => {
    setPhase('input');
    setScanResults(null);
    setError(null);
    setTargetUrl('');
    setAuthCookie('');
  };

  return (
    <div style={styles.app}>
      <header style={styles.header}>
        <div style={styles.logo}>
          <span style={styles.logoIcon}>◆</span>
          <span style={styles.logoText}>AEGIS</span>
          <span style={styles.logoSub}>SCANNER</span>
        </div>
        {phase === 'results' && (
          <button onClick={resetScan} style={styles.newScanBtn}>New Scan</button>
        )}
      </header>

      <main style={styles.main}>
        {phase === 'input' && (
          <ScanInput
            targetUrl={targetUrl}
            setTargetUrl={setTargetUrl}
            authCookie={authCookie}
            setAuthCookie={setAuthCookie}
            onStart={startScan}
            error={error}
          />
        )}
        {phase === 'scanning' && <ScanProgress progress={progress} />}
        {phase === 'results' && scanResults && (
          <ScanResults data={scanResults} />
        )}
      </main>

      <footer style={styles.footer}>
        AEGIS Scanner v1.0 — NIT6150 Advanced Project, NMIT / Victoria University
      </footer>
    </div>
  );
}

/* =======================================================================
   SCAN INPUT
   ======================================================================= */
function ScanInput({ targetUrl, setTargetUrl, authCookie, setAuthCookie, onStart, error }) {
  const [showAdvanced, setShowAdvanced] = useState(false);

  return (
    <div style={styles.inputContainer}>
      <div style={styles.inputCard}>
        <h1 style={styles.inputTitle}>Web Application Vulnerability Scanner</h1>
        <p style={styles.inputDesc}>
          Enter a target URL to scan for SQL Injection, Broken Access Control,
          Authentication Failures, and Security Misconfigurations.
        </p>

        {error && <div style={styles.errorBanner}>{error}</div>}

        <div style={styles.inputRow}>
          <input
            type="text"
            placeholder="http://localhost:8080"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && onStart()}
            style={styles.urlInput}
          />
          <button onClick={onStart} style={styles.scanBtn}>
            Scan Target
          </button>
        </div>

        <button
          onClick={() => setShowAdvanced(!showAdvanced)}
          style={styles.advancedToggle}
        >
          {showAdvanced ? '▾' : '▸'} Advanced Options
        </button>

        {showAdvanced && (
          <div style={styles.advancedBox}>
            <label style={styles.advLabel}>Auth Cookie (JSON)</label>
            <input
              type="text"
              placeholder='{"session": "abc123"}'
              value={authCookie}
              onChange={(e) => setAuthCookie(e.target.value)}
              style={styles.advInput}
            />
          </div>
        )}

        <div style={styles.scannerGrid}>
          {[
            { name: 'SQL Injection', id: 'A03:2021', color: '#dc2626', icon: '⚡' },
            { name: 'Broken Access Control', id: 'A01:2021', color: '#ea580c', icon: '🔓' },
            { name: 'Auth Failures', id: 'A07:2021', color: '#ca8a04', icon: '🔑' },
            { name: 'Misconfiguration', id: 'A05:2021', color: '#2563eb', icon: '⚙️' },
          ].map((s) => (
            <div key={s.id} style={{ ...styles.scannerCard, borderTopColor: s.color }}>
              <span style={styles.scannerIcon}>{s.icon}</span>
              <span style={styles.scannerName}>{s.name}</span>
              <span style={styles.scannerOwasp}>{s.id}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

/* =======================================================================
   SCAN PROGRESS
   ======================================================================= */
function ScanProgress({ progress }) {
  return (
    <div style={styles.progressContainer}>
      <div style={styles.progressCard}>
        <div style={styles.spinner} />
        <h2 style={styles.progressTitle}>Scanning in Progress</h2>
        <p style={styles.progressMsg}>{progress.message}</p>
        <div style={styles.progressBarOuter}>
          <div
            style={{ ...styles.progressBarInner, width: `${progress.pct}%` }}
          />
        </div>
        <p style={styles.progressPct}>{progress.pct}%</p>
      </div>
    </div>
  );
}

/* =======================================================================
   SCAN RESULTS
   ======================================================================= */
function ScanResults({ data }) {
  const risk = data.risk_prediction || {};
  const findings = data.findings || [];
  const recs = data.recommendations || {};
  const crawl = data.crawl_stats || {};
  const featuresSummary = risk.features_summary || {};

  return (
    <div style={styles.resultsContainer}>
      {/* Target banner */}
      <div style={styles.targetBanner}>
        <div>
          <span style={styles.targetLabel}>Target</span>
          <span style={styles.targetUrl}>{data.target_url}</span>
        </div>
        <div style={styles.targetMeta}>
          <span>Duration: {data.scan_duration}s</span>
          <span>Endpoints: {crawl.endpoints_discovered || 0}</span>
          <span>Findings: {findings.length}</span>
          {data.report_url && (
            <a
              href={`${API_BASE}${data.report_url}`}
              style={styles.pdfLink}
              target="_blank"
              rel="noreferrer"
            >
              ↓ PDF Report
            </a>
          )}
        </div>
      </div>

      {/* Severity cards + Risk gauge row */}
      <div style={styles.topRow}>
        <SeverityCards features={featuresSummary} />
        <RiskGauge risk={risk} />
      </div>

      {/* Charts row */}
      <div style={styles.chartsRow}>
        <OWASPChart findings={findings} recs={recs} />
        <SeverityPie features={featuresSummary} />
      </div>

      {/* Findings table */}
      <FindingsTable findings={findings} />

      {/* Recommendations */}
      <Recommendations recs={recs} />
    </div>
  );
}

/* =======================================================================
   SEVERITY CARDS
   ======================================================================= */
function SeverityCards({ features }) {
  const bySev = features.findings_by_severity || {};
  const cards = ['Critical', 'High', 'Medium', 'Low'].map((sev) => ({
    label: sev,
    count: bySev[sev] || 0,
    color: SEVERITY_COLORS[sev],
  }));

  return (
    <div style={styles.sevCardsGrid}>
      {cards.map((c) => (
        <div key={c.label} style={{ ...styles.sevCard, borderLeftColor: c.color }}>
          <span style={{ ...styles.sevCount, color: c.color }}>{c.count}</span>
          <span style={styles.sevLabel}>{c.label}</span>
        </div>
      ))}
    </div>
  );
}

/* =======================================================================
   RISK GAUGE
   ======================================================================= */
function RiskGauge({ risk }) {
  const level = risk.risk_level || 'Unknown';
  const confidence = risk.confidence || 0;
  const color = RISK_COLORS[level] || '#6b7280';

  const pct = Math.round(confidence * 100);
  const circumference = 2 * Math.PI * 54;
  const offset = circumference - (pct / 100) * circumference;

  return (
    <div style={styles.gaugeCard}>
      <svg width="140" height="140" viewBox="0 0 120 120">
        <circle cx="60" cy="60" r="54" fill="none" stroke="#e2e8f0" strokeWidth="8" />
        <circle
          cx="60" cy="60" r="54" fill="none"
          stroke={color} strokeWidth="8"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round"
          transform="rotate(-90 60 60)"
          style={{ transition: 'stroke-dashoffset 1s ease' }}
        />
        <text x="60" y="52" textAnchor="middle" fontSize="22" fontWeight="700" fill={color}>
          {pct}%
        </text>
        <text x="60" y="72" textAnchor="middle" fontSize="10" fill="#64748b">
          confidence
        </text>
      </svg>
      <div style={{ ...styles.gaugeLevel, color }}>{level.toUpperCase()}</div>
      <div style={styles.gaugeLabel}>ML Risk Prediction</div>
    </div>
  );
}

/* =======================================================================
   OWASP BAR CHART
   ======================================================================= */
function OWASPChart({ findings, recs }) {
  const owaspSummary = recs.owasp_summary || {};
  const chartData = Object.entries(owaspSummary).map(([cat, count]) => {
    const id = cat.split(' ')[0];
    return { name: cat, count, fill: OWASP_COLORS[id] || '#6b7280' };
  });

  if (chartData.length === 0) return null;

  return (
    <div style={styles.chartCard}>
      <h3 style={styles.chartTitle}>Findings by OWASP Category</h3>
      <ResponsiveContainer width="100%" height={220}>
        <BarChart data={chartData} layout="vertical" margin={{ left: 10, right: 20 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" />
          <XAxis type="number" allowDecimals={false} tick={{ fontSize: 12 }} />
          <YAxis
            type="category" dataKey="name" width={180}
            tick={{ fontSize: 11 }}
          />
          <Tooltip />
          <Bar dataKey="count" radius={[0, 4, 4, 0]}>
            {chartData.map((d, i) => (
              <Cell key={i} fill={d.fill} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

/* =======================================================================
   SEVERITY PIE CHART
   ======================================================================= */
function SeverityPie({ features }) {
  const bySev = features.findings_by_severity || {};
  const data = Object.entries(bySev)
    .filter(([, v]) => v > 0)
    .map(([sev, count]) => ({ name: sev, value: count }));

  if (data.length === 0) return null;

  return (
    <div style={styles.chartCard}>
      <h3 style={styles.chartTitle}>Severity Distribution</h3>
      <ResponsiveContainer width="100%" height={220}>
        <PieChart>
          <Pie
            data={data} dataKey="value" nameKey="name"
            cx="50%" cy="50%" outerRadius={80} innerRadius={40}
            paddingAngle={3}
          >
            {data.map((d, i) => (
              <Cell key={i} fill={SEVERITY_COLORS[d.name] || '#6b7280'} />
            ))}
          </Pie>
          <Legend iconType="circle" />
          <Tooltip />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}

/* =======================================================================
   FINDINGS TABLE
   ======================================================================= */
function FindingsTable({ findings }) {
  const [expandedIdx, setExpandedIdx] = useState(null);
  const [filter, setFilter] = useState('All');

  const severityOrder = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
  const sorted = [...findings].sort(
    (a, b) => (severityOrder[a.severity] || 5) - (severityOrder[b.severity] || 5)
  );
  const filtered = filter === 'All'
    ? sorted
    : sorted.filter((f) => f.severity === filter);

  return (
    <div style={styles.tableCard}>
      <div style={styles.tableHeader}>
        <h3 style={styles.chartTitle}>Findings ({findings.length})</h3>
        <div style={styles.filterRow}>
          {['All', 'Critical', 'High', 'Medium', 'Low'].map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              style={{
                ...styles.filterBtn,
                ...(filter === f ? styles.filterBtnActive : {}),
                ...(f !== 'All' ? { color: SEVERITY_COLORS[f] } : {}),
              }}
            >
              {f}
            </button>
          ))}
        </div>
      </div>

      <div style={styles.tableBody}>
        {filtered.map((f, i) => (
          <div key={i}>
            <div
              style={styles.tableRow}
              onClick={() => setExpandedIdx(expandedIdx === i ? null : i)}
            >
              <span style={{
                ...styles.sevBadge,
                backgroundColor: SEVERITY_COLORS[f.severity] + '18',
                color: SEVERITY_COLORS[f.severity],
              }}>
                {f.severity}
              </span>
              <span style={styles.findingType}>{f.vuln_type}</span>
              <span style={styles.findingUrl}>
                {f.method} {f.url?.length > 40 ? f.url.slice(0, 40) + '...' : f.url}
              </span>
              <span style={styles.findingParam}>{f.parameter || '—'}</span>
              <span style={styles.expandArrow}>
                {expandedIdx === i ? '▾' : '▸'}
              </span>
            </div>

            {expandedIdx === i && (
              <div style={styles.expandedRow}>
                <div style={styles.detailGrid}>
                  <Detail label="Confidence" value={f.confidence} />
                  <Detail label="Parameter" value={f.parameter} />
                  <Detail label="Payload" value={f.payload} />
                  <Detail label="Evidence" value={f.evidence} />
                </div>
                {f.details && (
                  <pre style={styles.detailJson}>
                    {JSON.stringify(f.details, null, 2)}
                  </pre>
                )}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

function Detail({ label, value }) {
  return (
    <div style={styles.detailItem}>
      <span style={styles.detailLabel}>{label}</span>
      <span style={styles.detailValue}>{value || '—'}</span>
    </div>
  );
}

/* =======================================================================
   RECOMMENDATIONS
   ======================================================================= */
function Recommendations({ recs }) {
  const recList = recs.recommendations || [];
  const [openIdx, setOpenIdx] = useState(null);

  if (recList.length === 0) return null;

  return (
    <div style={styles.tableCard}>
      <h3 style={styles.chartTitle}>
        Remediation Recommendations ({recList.length})
      </h3>
      {recList.map((rec, i) => (
        <div key={i} style={styles.recItem}>
          <div
            style={styles.recHeader}
            onClick={() => setOpenIdx(openIdx === i ? null : i)}
          >
            <span style={{
              ...styles.sevBadge,
              backgroundColor: SEVERITY_COLORS[rec.severity] + '18',
              color: SEVERITY_COLORS[rec.severity],
            }}>
              {rec.severity}
            </span>
            <span style={styles.recType}>{rec.finding_type}</span>
            <span style={styles.recOwasp}>{rec.owasp_id}</span>
            <span style={styles.expandArrow}>
              {openIdx === i ? '▾' : '▸'}
            </span>
          </div>

          {openIdx === i && (
            <div style={styles.recBody}>
              <p style={styles.recDesc}>{rec.description}</p>
              <h4 style={styles.recStepsTitle}>Remediation Steps:</h4>
              <ol style={styles.recStepsList}>
                {(rec.remediation_steps || []).map((step, j) => (
                  <li key={j} style={styles.recStep}>{step}</li>
                ))}
              </ol>
              {rec.references?.length > 0 && (
                <div style={styles.recRefs}>
                  {rec.references.map((ref, j) => (
                    <a key={j} href={ref} target="_blank" rel="noreferrer"
                       style={styles.recRefLink}>
                      {ref}
                    </a>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

/* =======================================================================
   STYLES
   ======================================================================= */
const styles = {
  app: {
    minHeight: '100vh',
    background: '#0f172a',
    color: '#e2e8f0',
    fontFamily: "'Outfit', sans-serif",
  },
  header: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: '16px 32px',
    borderBottom: '1px solid #1e293b',
  },
  logo: { display: 'flex', alignItems: 'center', gap: '8px' },
  logoIcon: { fontSize: '24px', color: '#3b82f6' },
  logoText: {
    fontSize: '20px', fontWeight: 800, letterSpacing: '2px', color: '#f1f5f9',
  },
  logoSub: {
    fontSize: '12px', fontWeight: 400, color: '#64748b', letterSpacing: '3px',
    marginTop: '2px',
  },
  newScanBtn: {
    background: 'none', border: '1px solid #334155', borderRadius: '6px',
    color: '#94a3b8', padding: '8px 16px', cursor: 'pointer',
    fontFamily: "'Outfit', sans-serif", fontSize: '13px',
  },
  main: { maxWidth: '1200px', margin: '0 auto', padding: '24px 32px' },
  footer: {
    textAlign: 'center', padding: '24px', color: '#475569', fontSize: '12px',
    borderTop: '1px solid #1e293b',
  },

  /* Input */
  inputContainer: {
    display: 'flex', justifyContent: 'center', alignItems: 'center',
    minHeight: '70vh',
  },
  inputCard: {
    background: '#1e293b', borderRadius: '12px', padding: '48px',
    maxWidth: '700px', width: '100%', border: '1px solid #334155',
  },
  inputTitle: {
    fontSize: '28px', fontWeight: 700, marginBottom: '8px', color: '#f1f5f9',
  },
  inputDesc: { color: '#94a3b8', marginBottom: '24px', lineHeight: '1.6' },
  errorBanner: {
    background: '#dc262620', border: '1px solid #dc262660', borderRadius: '8px',
    padding: '12px', color: '#fca5a5', marginBottom: '16px', fontSize: '14px',
  },
  inputRow: { display: 'flex', gap: '12px', marginBottom: '12px' },
  urlInput: {
    flex: 1, padding: '14px 16px', borderRadius: '8px', border: '1px solid #334155',
    background: '#0f172a', color: '#f1f5f9', fontSize: '15px',
    fontFamily: "'JetBrains Mono', monospace", outline: 'none',
  },
  scanBtn: {
    padding: '14px 28px', borderRadius: '8px', border: 'none',
    background: '#3b82f6', color: 'white', fontSize: '15px', fontWeight: 600,
    cursor: 'pointer', fontFamily: "'Outfit', sans-serif",
    whiteSpace: 'nowrap',
  },
  advancedToggle: {
    background: 'none', border: 'none', color: '#64748b', cursor: 'pointer',
    fontSize: '13px', padding: '4px 0', marginBottom: '8px',
    fontFamily: "'Outfit', sans-serif",
  },
  advancedBox: { marginBottom: '16px' },
  advLabel: { fontSize: '13px', color: '#94a3b8', display: 'block', marginBottom: '4px' },
  advInput: {
    width: '100%', padding: '10px 12px', borderRadius: '6px',
    border: '1px solid #334155', background: '#0f172a', color: '#f1f5f9',
    fontSize: '13px', fontFamily: "'JetBrains Mono', monospace",
    outline: 'none', boxSizing: 'border-box',
  },
  scannerGrid: {
    display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '12px',
    marginTop: '24px',
  },
  scannerCard: {
    background: '#0f172a', borderRadius: '8px', padding: '16px',
    borderTop: '3px solid', textAlign: 'center',
  },
  scannerIcon: { fontSize: '24px', display: 'block', marginBottom: '8px' },
  scannerName: {
    fontSize: '13px', fontWeight: 600, color: '#e2e8f0', display: 'block',
  },
  scannerOwasp: { fontSize: '11px', color: '#64748b' },

  /* Progress */
  progressContainer: {
    display: 'flex', justifyContent: 'center', alignItems: 'center',
    minHeight: '60vh',
  },
  progressCard: {
    background: '#1e293b', borderRadius: '12px', padding: '48px',
    textAlign: 'center', border: '1px solid #334155', width: '500px',
  },
  spinner: {
    width: '48px', height: '48px', border: '4px solid #334155',
    borderTop: '4px solid #3b82f6', borderRadius: '50%',
    animation: 'spin 1s linear infinite', margin: '0 auto 24px',
  },
  progressTitle: { fontSize: '20px', fontWeight: 600, marginBottom: '8px' },
  progressMsg: { color: '#94a3b8', marginBottom: '20px', fontSize: '14px' },
  progressBarOuter: {
    height: '8px', background: '#0f172a', borderRadius: '4px', overflow: 'hidden',
  },
  progressBarInner: {
    height: '100%', background: 'linear-gradient(90deg, #3b82f6, #8b5cf6)',
    borderRadius: '4px', transition: 'width 0.5s ease',
  },
  progressPct: { color: '#64748b', fontSize: '14px', marginTop: '8px' },

  /* Results */
  resultsContainer: { display: 'flex', flexDirection: 'column', gap: '20px' },
  targetBanner: {
    display: 'flex', justifyContent: 'space-between', alignItems: 'center',
    background: '#1e293b', borderRadius: '10px', padding: '16px 24px',
    border: '1px solid #334155', flexWrap: 'wrap', gap: '12px',
  },
  targetLabel: {
    fontSize: '11px', color: '#64748b', textTransform: 'uppercase',
    letterSpacing: '1px', display: 'block',
  },
  targetUrl: {
    fontSize: '18px', fontWeight: 600, color: '#f1f5f9',
    fontFamily: "'JetBrains Mono', monospace",
  },
  targetMeta: {
    display: 'flex', gap: '20px', color: '#94a3b8', fontSize: '13px',
    flexWrap: 'wrap',
  },
  pdfLink: {
    color: '#3b82f6', textDecoration: 'none', fontWeight: 600,
  },

  /* Top row */
  topRow: { display: 'flex', gap: '20px' },
  sevCardsGrid: {
    flex: 1, display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '12px',
  },
  sevCard: {
    background: '#1e293b', borderRadius: '10px', padding: '20px',
    borderLeft: '4px solid', border: '1px solid #334155',
  },
  sevCount: { fontSize: '32px', fontWeight: 700, display: 'block' },
  sevLabel: { fontSize: '13px', color: '#94a3b8' },
  gaugeCard: {
    background: '#1e293b', borderRadius: '10px', padding: '24px',
    border: '1px solid #334155', textAlign: 'center',
    display: 'flex', flexDirection: 'column', alignItems: 'center',
    justifyContent: 'center', minWidth: '200px',
  },
  gaugeLevel: { fontSize: '18px', fontWeight: 700, marginTop: '8px' },
  gaugeLabel: { fontSize: '12px', color: '#64748b', marginTop: '4px' },

  /* Charts */
  chartsRow: { display: 'flex', gap: '20px' },
  chartCard: {
    flex: 1, background: '#1e293b', borderRadius: '10px', padding: '20px',
    border: '1px solid #334155',
  },
  chartTitle: {
    fontSize: '14px', fontWeight: 600, color: '#e2e8f0', marginBottom: '16px',
    marginTop: 0,
  },

  /* Findings table */
  tableCard: {
    background: '#1e293b', borderRadius: '10px', padding: '20px',
    border: '1px solid #334155',
  },
  tableHeader: {
    display: 'flex', justifyContent: 'space-between', alignItems: 'center',
    marginBottom: '12px', flexWrap: 'wrap', gap: '8px',
  },
  filterRow: { display: 'flex', gap: '6px' },
  filterBtn: {
    background: 'none', border: '1px solid #334155', borderRadius: '6px',
    color: '#94a3b8', padding: '4px 12px', cursor: 'pointer', fontSize: '12px',
    fontFamily: "'Outfit', sans-serif",
  },
  filterBtnActive: {
    background: '#334155', borderColor: '#475569',
  },
  tableBody: { maxHeight: '500px', overflowY: 'auto' },
  tableRow: {
    display: 'grid',
    gridTemplateColumns: '90px 1fr 1fr 120px 30px',
    alignItems: 'center', gap: '12px',
    padding: '12px 8px', borderBottom: '1px solid #0f172a',
    cursor: 'pointer', fontSize: '13px',
  },
  sevBadge: {
    padding: '3px 10px', borderRadius: '6px', fontSize: '11px',
    fontWeight: 600, textAlign: 'center', display: 'inline-block',
  },
  findingType: { fontWeight: 500, color: '#e2e8f0' },
  findingUrl: {
    color: '#94a3b8', fontFamily: "'JetBrains Mono', monospace", fontSize: '12px',
  },
  findingParam: { color: '#64748b', fontSize: '12px' },
  expandArrow: { color: '#475569', textAlign: 'right' },
  expandedRow: {
    background: '#0f172a', padding: '16px', borderRadius: '8px',
    marginBottom: '8px',
  },
  detailGrid: {
    display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '12px',
    marginBottom: '12px',
  },
  detailItem: {},
  detailLabel: {
    display: 'block', fontSize: '11px', color: '#64748b',
    textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '2px',
  },
  detailValue: {
    fontSize: '13px', color: '#cbd5e1', wordBreak: 'break-word',
  },
  detailJson: {
    background: '#1e293b', padding: '12px', borderRadius: '6px',
    fontSize: '11px', color: '#94a3b8', overflow: 'auto', maxHeight: '200px',
    fontFamily: "'JetBrains Mono', monospace",
  },

  /* Recommendations */
  recItem: {
    borderBottom: '1px solid #0f172a', marginBottom: '4px',
  },
  recHeader: {
    display: 'grid',
    gridTemplateColumns: '90px 1fr 80px 30px',
    alignItems: 'center', gap: '12px',
    padding: '12px 8px', cursor: 'pointer', fontSize: '13px',
  },
  recType: { fontWeight: 500, color: '#e2e8f0' },
  recOwasp: { color: '#64748b', fontSize: '12px', textAlign: 'right' },
  recBody: {
    background: '#0f172a', padding: '16px', borderRadius: '8px',
    marginBottom: '8px',
  },
  recDesc: { color: '#94a3b8', fontSize: '13px', lineHeight: '1.6', marginTop: 0 },
  recStepsTitle: {
    fontSize: '13px', fontWeight: 600, color: '#e2e8f0', margin: '12px 0 8px',
  },
  recStepsList: { paddingLeft: '20px', margin: 0 },
  recStep: {
    color: '#cbd5e1', fontSize: '13px', lineHeight: '1.6', marginBottom: '6px',
  },
  recRefs: {
    marginTop: '12px', display: 'flex', flexDirection: 'column', gap: '4px',
  },
  recRefLink: {
    color: '#3b82f6', fontSize: '12px', textDecoration: 'none',
    wordBreak: 'break-all',
  },
};

/* Inject spinner animation */
const styleSheet = document.createElement('style');
styleSheet.textContent = `
  @keyframes spin { to { transform: rotate(360deg); } }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { margin: 0; }
  ::-webkit-scrollbar { width: 6px; }
  ::-webkit-scrollbar-track { background: #0f172a; }
  ::-webkit-scrollbar-thumb { background: #334155; border-radius: 3px; }
`;
document.head.appendChild(styleSheet);