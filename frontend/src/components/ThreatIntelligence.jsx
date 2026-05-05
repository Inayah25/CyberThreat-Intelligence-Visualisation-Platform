import { useState, useEffect } from 'react';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip as RTooltip,
  ResponsiveContainer, Cell,
} from 'recharts';
import { api } from '../services/api';

// ─── UI-only abbreviation map (presentation, not data) ───────────────────────

const TACTIC_SHORT = {
  'Reconnaissance': 'Recon',
  'Resource Development': 'Res Dev',
  'Initial Access': 'Init Access',
  'Execution': 'Exec',
  'Persistence': 'Persist',
  'Privilege Escalation': 'Priv Esc',
  'Defense Evasion': 'Def Evas',
  'Credential Access': 'Cred Access',
  'Discovery': 'Discovery',
  'Lateral Movement': 'Lateral',
  'Collection': 'Collect',
  'Command & Control': 'C2',
  'Exfiltration': 'Exfil',
  'Impact': 'Impact',
};

// ─── Severity helpers ─────────────────────────────────────────────────────────

const SEV_STYLE = {
  CRITICAL: 'bg-red-950 border-red-800 text-red-400',
  HIGH:     'bg-orange-950 border-orange-800 text-orange-400',
  MEDIUM:   'bg-yellow-950 border-yellow-800 text-yellow-400',
  LOW:      'bg-purple-950 border-purple-900 text-purple-400',
};

const SEV_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

function Badge({ level, children }) {
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-bold border ${SEV_STYLE[level] || SEV_STYLE.LOW}`}>
      {children ?? level}
    </span>
  );
}

// ─── Collapsible Panel ────────────────────────────────────────────────────────

function Panel({ title, subtitle, badge, summary, children }) {
  const [open, setOpen] = useState(false);
  return (
    <section className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full text-left p-6 hover:bg-gray-800/30 transition-colors"
      >
        <div className="flex items-start justify-between gap-4">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <h3 className="text-white font-semibold">{title}</h3>
              {badge}
            </div>
            {subtitle && <p className="text-gray-400 text-sm mt-0.5">{subtitle}</p>}
            {summary && <div className="mt-3">{summary}</div>}
          </div>
          <div className={`shrink-0 text-gray-500 text-xs mt-1 transition-transform duration-200 select-none ${open ? 'rotate-180' : ''}`}>
            ▼
          </div>
        </div>
        <p className="text-gray-600 text-xs mt-3 text-right">
          {open ? '▲ collapse' : '▼ expand for full detail'}
        </p>
      </button>
      {open && (
        <div className="border-t border-gray-800 px-6 py-5">
          {children}
        </div>
      )}
    </section>
  );
}

// ─── Matrix color ─────────────────────────────────────────────────────────────

function matrixColor(val, max) {
  if (!val) return '#0f172a';
  const t = Math.min(val / max, 1);
  if (t > 0.7)  return '#991b1b'; // red
  if (t > 0.4)  return '#c2410c'; // orange
  if (t > 0.1)  return '#6d28d9'; // violet
  return '#1e1b4b';               // indigo (any activity)
}

// ─── Main Component ───────────────────────────────────────────────────────────

export default function ThreatIntelligence() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [fetchError, setFetchError] = useState(null);

  useEffect(() => {
    api.threatMapping()
      .then(res => { setData(res); setLoading(false); })
      .catch(err => { setFetchError(err.message); setLoading(false); });
  }, []);

  if (loading) {
    return (
      <div className="space-y-6">
        {[...Array(4)].map((_, i) => (
          <div key={i} className="bg-gray-900 border border-gray-800 rounded-xl p-6">
            <div className="animate-pulse h-24 bg-gray-800 rounded" />
          </div>
        ))}
      </div>
    );
  }

  if (fetchError || !data) {
    return (
      <div className="bg-red-950 border border-red-800 rounded-xl px-6 py-5 text-red-400">
        <span className="font-semibold">Failed to load threat intelligence data.</span>
        {fetchError && <span className="text-red-500 text-sm ml-2">{fetchError}</span>}
      </div>
    );
  }

  const {
    attack_loaded,
    attack_version,
    techniques,
    brute_techniques,
    brute_summary,
    tactic_totals,
    all_tactics,
    active_tactics,
    matrix,
  } = data;

  // ── Deduped technique frequency chart data ────────────────────────────────

  const techFreqMap = {};
  techniques.forEach(r => {
    if (!techFreqMap[r.id]) {
      techFreqMap[r.id] = { id: r.id, name: r.name, tactic: r.tactic, count: 0 };
    }
    techFreqMap[r.id].count += r.event_count;
  });
  const techFreqList = Object.values(techFreqMap).sort((a, b) => b.count - a.count);

  // ── Control gap rows (mitigations already embedded in each technique row) ─

  const gapMap = new Map();
  [...techniques, ...brute_techniques].forEach(row => {
    (row.mitigations || []).forEach(m => {
      const key = `${row.id}-${m.id}`;
      if (!gapMap.has(key)) {
        gapMap.set(key, {
          techId: row.id,
          techName: row.name,
          mitId: m.id,
          mitName: m.name,
          count: row.event_count,
          sev: row.severity,
        });
      }
    });
  });
  const gapRows = [...gapMap.values()].sort(
    (a, b) => (SEV_ORDER[a.sev] ?? 3) - (SEV_ORDER[b.sev] ?? 3),
  );
  const criticalGaps = gapRows.filter(r => r.sev === 'CRITICAL').length;

  // ── Matrix ────────────────────────────────────────────────────────────────

  const matrixSources = Object.keys(matrix);
  const matrixMax = Math.max(
    1,
    ...Object.values(matrix).flatMap(row => Object.values(row)),
  );

  // ── Unique technique IDs (for summary pills) ──────────────────────────────

  const uniqueTechIds = [...new Set(techniques.map(r => r.id))];

  return (
    <div className="space-y-6">

      {/* ── ATT&CK data status banner ──────────────────────────────────────── */}
      {!attack_loaded ? (
        <div className="bg-yellow-950 border border-yellow-800 rounded-xl px-5 py-3 flex items-start gap-3">
          <span className="text-yellow-400 text-lg shrink-0">⚠</span>
          <div>
            <p className="text-yellow-400 text-sm font-semibold">MITRE ATT&CK data unavailable</p>
            <p className="text-yellow-600 text-xs mt-0.5">
              Technique names, descriptions and mitigations could not be loaded from GitHub.
              Check backend logs. Events are still counted from honeypot data.
            </p>
          </div>
        </div>
      ) : (
        <div className="flex items-center gap-2 text-xs text-gray-500">
          <span className="h-1.5 w-1.5 rounded-full bg-green-500 inline-block" />
          {attack_version && attack_version !== 'unknown'
            ? `MITRE ATT&CK v${attack_version} — live data from mitre-attack/attack-stix-data`
            : 'MITRE ATT&CK live data loaded'}
        </div>
      )}

      {/* ── 1. Tactics Coverage Matrix ──────────────────────────────────────── */}
      <section className="bg-gray-900 border border-gray-800 rounded-xl p-6">
        <h3 className="text-white font-semibold mb-0.5">MITRE ATT&CK Tactics Coverage</h3>
        <p className="text-gray-400 text-sm mb-5">
          <span className="text-purple-400 font-semibold">
            {Object.keys(tactic_totals).filter(t => tactic_totals[t] > 0).length}
          </span>
          {' '}of 14 tactics detected
        </p>
        <div className="grid grid-cols-7 gap-2">
          {all_tactics.map(tactic => {
            const count = tactic_totals[tactic] || 0;
            const active = count > 0;
            return (
              <div
                key={tactic}
                className={`rounded-lg p-2.5 text-center border ${
                  active
                    ? 'bg-purple-950 border-purple-700'
                    : 'bg-gray-800 border-gray-700 opacity-35'
                }`}
              >
                <div className={`text-xs font-medium leading-tight ${active ? 'text-purple-200' : 'text-gray-500'}`}>
                  {TACTIC_SHORT[tactic] || tactic}
                </div>
                {active
                  ? <div className="text-purple-400 text-xs font-bold mt-1">
                      {count > 999 ? `${(count / 1000).toFixed(0)}k` : count}
                    </div>
                  : <div className="text-gray-600 text-xs mt-1">—</div>
                }
              </div>
            );
          })}
        </div>
      </section>

      {/* ── 2. ATT&CK Technique Mapping ─────────────────────────────────────── */}
      <Panel
        title="ATT&CK Technique Mapping"
        subtitle="Detected attack sources mapped to MITRE ATT&CK techniques"
        badge={<Badge level="HIGH">{uniqueTechIds.length} techniques</Badge>}
        summary={
          <div className="flex flex-wrap gap-1.5">
            {uniqueTechIds.slice(0, 5).map(id => {
              const row = techniques.find(r => r.id === id);
              return (
                <span key={id} className="inline-flex items-center gap-1.5 px-2.5 py-1 bg-gray-800 border border-gray-700 rounded-full text-xs">
                  <span className="text-purple-400 font-mono font-semibold">{id}</span>
                  <span className="text-gray-300">{row?.name}</span>
                </span>
              );
            })}
            {uniqueTechIds.length > 5 && (
              <span className="text-gray-500 text-xs self-center">+{uniqueTechIds.length - 5} more</span>
            )}
          </div>
        }
      >
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-700 text-gray-400 text-xs uppercase tracking-wide">
                <th className="text-left py-2 pr-4 font-medium">Source</th>
                <th className="text-left py-2 pr-4 font-medium">Technique ID</th>
                <th className="text-left py-2 pr-4 font-medium">Name</th>
                <th className="text-left py-2 pr-4 font-medium">Tactic</th>
                <th className="text-right py-2 pr-4 font-medium">Events</th>
                <th className="text-right py-2 font-medium">Severity</th>
              </tr>
            </thead>
            <tbody>
              {techniques.map((row, i) => (
                <tr key={i} className="border-b border-gray-800 hover:bg-gray-800/40 transition-colors">
                  <td className="py-2.5 pr-4 text-gray-200 font-medium">{row.source}</td>
                  <td className="py-2.5 pr-4 font-mono text-purple-400 text-xs">{row.id}</td>
                  <td className="py-2.5 pr-4 text-gray-300">{row.name}</td>
                  <td className="py-2.5 pr-4 text-gray-400 text-xs">{row.tactic}</td>
                  <td className="py-2.5 pr-4 text-right text-gray-300">{row.event_count.toLocaleString()}</td>
                  <td className="py-2.5 text-right"><Badge level={row.severity} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>

      {/* ── 3 + 4. Technique Frequency + Brute Force Intel (2-col) ─────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

        {/* Technique Frequency */}
        <Panel
          title="Technique Frequency"
          subtitle="Most observed ATT&CK techniques by event count"
          summary={
            <div className="flex items-end gap-0.5 h-8">
              {techFreqList.slice(0, 6).map((t, i) => (
                <div
                  key={t.id}
                  className="bg-purple-600 rounded-sm flex-1"
                  style={{
                    height: `${Math.max(15, Math.round((t.count / (techFreqList[0]?.count || 1)) * 100))}%`,
                    opacity: 1 - i * 0.12,
                  }}
                  title={`${t.id}: ${t.count.toLocaleString()}`}
                />
              ))}
            </div>
          }
        >
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={techFreqList} layout="vertical" margin={{ left: 88, right: 16, top: 4, bottom: 4 }}>
              <XAxis
                type="number"
                tick={{ fill: '#6b7280', fontSize: 11 }}
                tickFormatter={v => v >= 1000 ? `${(v / 1000).toFixed(0)}k` : v}
              />
              <YAxis
                type="category"
                dataKey="id"
                tick={{ fill: '#a78bfa', fontSize: 11, fontFamily: 'monospace' }}
                width={88}
              />
              <RTooltip
                contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: 8, fontSize: 12 }}
                labelStyle={{ color: '#e5e7eb' }}
                formatter={(v, _, { payload }) => [`${v.toLocaleString()} events`, payload.name]}
              />
              <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                {techFreqList.map((_, i) => (
                  <Cell key={i} fill={`hsl(${270 - i * 14}, 68%, ${63 - i * 2}%)`} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </Panel>

        {/* Brute Force Intelligence */}
        <Panel
          title="Brute Force Intelligence"
          subtitle="SSH brute force mapped to ATT&CK sub-techniques"
          badge={<Badge level="CRITICAL">CRITICAL</Badge>}
          summary={
            <div className="grid grid-cols-2 gap-3">
              <div className="bg-gray-800 border border-gray-700 rounded-lg p-3">
                <div className="text-xs text-gray-400 mb-1">Total Attempts</div>
                <div className="text-white font-bold text-lg">
                  {(brute_summary?.total_attempts || 0).toLocaleString()}
                </div>
                <div className="text-purple-400 text-xs mt-0.5 font-mono">T1110 · Credential Access</div>
              </div>
              <div className="bg-red-950 border border-red-900 rounded-lg p-3">
                <div className="text-xs text-red-300 mb-1">Default Credentials</div>
                <div className="text-red-400 font-bold text-lg">
                  {(brute_summary?.default_credential_pct || 0).toFixed(1)}%
                </div>
                <div className="text-red-500 text-xs mt-0.5 font-mono">T1078.001 · Default Accounts</div>
              </div>
            </div>
          }
        >
          <div className="space-y-2 mt-1">
            {brute_techniques.map(t => {
              const style = SEV_STYLE[t.severity] || SEV_STYLE.LOW;
              return (
                <div key={t.id} className={`rounded-lg p-3.5 border ${style}`}>
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <div className="flex items-center gap-2 mb-0.5">
                        <span className="font-mono text-xs text-purple-400">{t.id}</span>
                        <span className="text-white text-sm font-medium">{t.name}</span>
                      </div>
                      <div className="text-gray-400 text-xs">{t.tactic}</div>
                      {t.description && (
                        <div className="text-gray-500 text-xs mt-1 line-clamp-2">{t.description}</div>
                      )}
                    </div>
                    <div className="text-right shrink-0">
                      <Badge level={t.severity} />
                      <div className="text-xs mt-1 text-gray-300">{t.event_count.toLocaleString()} events</div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </Panel>
      </div>

      {/* ── 5. Control Gap Analysis ─────────────────────────────────────────── */}
      <Panel
        title="Control Gap Analysis"
        subtitle="Recommended MITRE mitigations for all detected techniques"
        badge={criticalGaps > 0 ? <Badge level="CRITICAL">{criticalGaps} critical gaps</Badge> : null}
        summary={
          <div className="flex flex-wrap gap-1.5">
            {gapRows.slice(0, 3).map((r, i) => (
              <span key={i} className="inline-flex items-center gap-1.5 px-2.5 py-1 bg-gray-800 border border-gray-700 rounded-full text-xs">
                <span className="text-green-400 font-mono font-semibold">{r.mitId}</span>
                <span className="text-gray-300">{r.mitName}</span>
              </span>
            ))}
            {gapRows.length > 3 && (
              <span className="text-gray-500 text-xs self-center">+{gapRows.length - 3} more</span>
            )}
          </div>
        }
      >
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-700 text-gray-400 text-xs uppercase tracking-wide">
                <th className="text-left py-2 pr-4 font-medium">Severity</th>
                <th className="text-left py-2 pr-4 font-medium">Technique</th>
                <th className="text-left py-2 pr-4 font-medium">Mitigation</th>
                <th className="text-left py-2 pr-4 font-medium">Recommendation</th>
                <th className="text-right py-2 font-medium">Events</th>
              </tr>
            </thead>
            <tbody>
              {gapRows.map((r, i) => (
                <tr key={i} className="border-b border-gray-800 hover:bg-gray-800/40 transition-colors">
                  <td className="py-2.5 pr-4"><Badge level={r.sev} /></td>
                  <td className="py-2.5 pr-4">
                    <span className="font-mono text-purple-400 text-xs">{r.techId}</span>
                    <span className="text-gray-400 text-xs ml-2">{r.techName}</span>
                  </td>
                  <td className="py-2.5 pr-4 font-mono text-green-400 text-xs font-semibold">{r.mitId}</td>
                  <td className="py-2.5 pr-4 text-gray-200">{r.mitName}</td>
                  <td className="py-2.5 text-right text-gray-400 text-xs">{r.count.toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>

      {/* ── 6. Combined Evidence Matrix ─────────────────────────────────────── */}
      <section className="bg-gray-900 border border-gray-800 rounded-xl p-6">
        <h3 className="text-white font-semibold mb-0.5">Combined Tactics Activity Matrix</h3>
        <p className="text-gray-400 text-sm mb-5">Attack evidence by data source × MITRE tactic</p>
        <div className="overflow-x-auto">
          <div className="inline-block">
            {/* Column headers */}
            <div className="flex ml-28 mb-1 gap-1">
              {active_tactics.map(t => (
                <div key={t} className="w-16 text-center text-gray-500 text-xs leading-tight">
                  {TACTIC_SHORT[t] || t}
                </div>
              ))}
            </div>
            {/* Data rows */}
            {matrixSources.map(src => (
              <div key={src} className="flex gap-1 mb-1 items-center">
                <div className="w-28 text-gray-400 text-xs shrink-0 pr-2 truncate">{src}</div>
                {active_tactics.map(tactic => {
                  const val = matrix[src]?.[tactic] || 0;
                  const bg = matrixColor(val, matrixMax);
                  return (
                    <div
                      key={tactic}
                      className="w-16 h-9 rounded-sm flex items-center justify-center transition-transform hover:scale-105"
                      style={{ backgroundColor: bg }}
                      title={`${src} × ${tactic}: ${val.toLocaleString()} events`}
                    >
                      {val > 0 && (
                        <span className="text-white text-xs font-semibold select-none">
                          {val >= 1000 ? `${(val / 1000).toFixed(0)}k` : val}
                        </span>
                      )}
                    </div>
                  );
                })}
              </div>
            ))}
          </div>
        </div>
        {/* Legend */}
        <div className="flex items-center gap-3 mt-5">
          <span className="text-gray-500 text-xs">None</span>
          <div className="h-2.5 rounded max-w-[200px] flex-1" style={{
            background: 'linear-gradient(to right, #1e1b4b, #6d28d9, #c2410c, #991b1b)',
          }} />
          <span className="text-gray-500 text-xs">Peak</span>
        </div>
      </section>

    </div>
  );
}
