import { useState, useEffect } from 'react';
import { api } from '../services/api';

const DATASET_OPTIONS = [
  { value: 'both', label: 'Both' },
  { value: 'honeynet', label: 'Honeynet Data' },
  { value: 'brute_force', label: 'Brute Force Data' },
];

const ATTACK_TYPE_OPTIONS = ['all', 'Cowrie', 'Dionaea', 'Sentrypeer'];
const PASSWORD_TYPE_OPTIONS = ['all', 'numeric', 'alpha', 'alphanumeric', 'special'];

function StatsTable({ rows, col1, col2 }) {
  if (!rows || rows.length === 0) return <p className="text-gray-500 text-sm">No data</p>;
  const nameKey = 'name' in rows[0] ? 'name' : 'type';
  return (
    <table className="w-full text-sm">
      <thead>
        <tr className="border-b border-gray-700 text-gray-400 text-xs uppercase tracking-wide">
          <th className="text-left py-2 pr-4 font-medium">{col1}</th>
          <th className="text-right py-2 font-medium">{col2}</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((r, i) => (
          <tr key={i} className="border-b border-gray-800 hover:bg-gray-800/40 transition-colors">
            <td className="py-2 pr-4 text-gray-300">{r[nameKey]}</td>
            <td className="py-2 text-right text-purple-400 font-semibold">{r.count.toLocaleString()}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export default function Reports() {
  // ── Filter state ──────────────────────────────────────────────────────────
  const [dataset, setDataset] = useState('both');
  const [attackType, setAttackType] = useState('all');
  const [country, setCountry] = useState('all');
  const [protocol, setProtocol] = useState('all');
  const [passwordType, setPasswordType] = useState('all');
  const [defaultOnly, setDefaultOnly] = useState(false);

  // ── Dropdown options (fetched once) ────────────────────────────────────────
  const [countryOptions, setCountryOptions] = useState([]);
  const [protocolOptions, setProtocolOptions] = useState([]);

  // ── Preview / download state ───────────────────────────────────────────────
  const [preview, setPreview] = useState(null);
  const [loadingPreview, setLoadingPreview] = useState(false);
  const [loadingPdf, setLoadingPdf] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    Promise.all([api.countries(100), api.protocols()])
      .then(([c, p]) => {
        setCountryOptions((c.data || []).map(x => x.country));
        setProtocolOptions((p.data || []).map(x => x.protocol));
      })
      .catch(console.error);
  }, []);

  const showHoneynet = dataset === 'honeynet' || dataset === 'both';
  const showBrute = dataset === 'brute_force' || dataset === 'both';

  const buildFilters = () => ({
    dataset,
    attack_type: attackType,
    country,
    protocol,
    password_type: passwordType,
    default_only: defaultOnly,
  });

  const handlePreview = () => {
    setLoadingPreview(true);
    setError(null);
    setPreview(null);
    api.reportPreview(buildFilters())
      .then(data => { setPreview(data); setLoadingPreview(false); })
      .catch(err => { setError(err.message); setLoadingPreview(false); });
  };

  const handleDownloadPdf = () => {
    setLoadingPdf(true);
    api.generateReport(buildFilters())
      .then(blob => {
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.setAttribute('download', 'cyber_attack_report.pdf');
        document.body.appendChild(link);
        link.click();
        link.remove();
        window.URL.revokeObjectURL(url);
        setLoadingPdf(false);
      })
      .catch(err => { setError(err.message); setLoadingPdf(false); });
  };

  return (
    <div className="space-y-8">
      {/* Page header */}
      <div>
        <h1 className="text-2xl font-bold text-white">Generate Report</h1>
        <p className="text-gray-400 text-sm mt-1">Filter and download a custom intelligence report</p>
      </div>

      {/* ── Filters panel ──────────────────────────────────────────────────── */}
      <section className="bg-gray-900 border border-gray-800 rounded-xl p-6">
        <h2 className="text-white font-semibold mb-4">Report Filters</h2>

        {/* Dataset selector */}
        <div className="mb-5">
          <label className="text-gray-400 text-xs uppercase tracking-wider block mb-2">Dataset</label>
          <div className="flex gap-1 bg-gray-800 rounded-lg p-1 w-fit">
            {DATASET_OPTIONS.map(opt => (
              <button
                key={opt.value}
                onClick={() => setDataset(opt.value)}
                className={`px-4 py-1.5 rounded text-xs font-medium transition-colors ${
                  dataset === opt.value
                    ? 'bg-purple-600 text-white'
                    : 'text-gray-400 hover:text-white'
                }`}
              >
                {opt.label}
              </button>
            ))}
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mb-5">
          {/* Honeynet filters */}
          {showHoneynet && (
            <>
              <div>
                <label className="text-gray-400 text-xs uppercase tracking-wider block mb-1.5">Attack Type</label>
                <select
                  value={attackType}
                  onChange={e => setAttackType(e.target.value)}
                  className="w-full bg-gray-800 border border-gray-700 text-gray-300 text-sm rounded-lg px-3 py-2"
                >
                  {ATTACK_TYPE_OPTIONS.map(o => (
                    <option key={o} value={o}>{o === 'all' ? 'All Attack Types' : o}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="text-gray-400 text-xs uppercase tracking-wider block mb-1.5">Country</label>
                <select
                  value={country}
                  onChange={e => setCountry(e.target.value)}
                  className="w-full bg-gray-800 border border-gray-700 text-gray-300 text-sm rounded-lg px-3 py-2"
                >
                  <option value="all">All Countries</option>
                  {countryOptions.map(c => (
                    <option key={c} value={c}>{c}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="text-gray-400 text-xs uppercase tracking-wider block mb-1.5">Protocol</label>
                <select
                  value={protocol}
                  onChange={e => setProtocol(e.target.value)}
                  className="w-full bg-gray-800 border border-gray-700 text-gray-300 text-sm rounded-lg px-3 py-2"
                >
                  <option value="all">All Protocols</option>
                  {protocolOptions.map(p => (
                    <option key={p} value={p}>{p}</option>
                  ))}
                </select>
              </div>
            </>
          )}

          {/* Brute force filters */}
          {showBrute && (
            <>
              <div>
                <label className="text-gray-400 text-xs uppercase tracking-wider block mb-1.5">Password Type</label>
                <select
                  value={passwordType}
                  onChange={e => setPasswordType(e.target.value)}
                  className="w-full bg-gray-800 border border-gray-700 text-gray-300 text-sm rounded-lg px-3 py-2"
                >
                  {PASSWORD_TYPE_OPTIONS.map(o => (
                    <option key={o} value={o}>{o === 'all' ? 'All Password Types' : o.charAt(0).toUpperCase() + o.slice(1)}</option>
                  ))}
                </select>
              </div>
              <div className="flex items-end">
                <label className="flex items-center gap-2.5 cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={defaultOnly}
                    onChange={e => setDefaultOnly(e.target.checked)}
                    className="w-4 h-4 rounded border-gray-600 bg-gray-800 text-purple-600 focus:ring-purple-500"
                  />
                  <span className="text-gray-300 text-sm">Default Credentials Only</span>
                </label>
              </div>
            </>
          )}
        </div>

        <button
          onClick={handlePreview}
          disabled={loadingPreview}
          className="px-6 py-2.5 bg-purple-600 hover:bg-purple-700 disabled:opacity-50 text-white text-sm font-medium rounded-lg transition-colors"
        >
          {loadingPreview ? 'Generating Preview…' : 'Generate Report Preview'}
        </button>
      </section>

      {/* ── Error ──────────────────────────────────────────────────────────── */}
      {error && (
        <div className="bg-red-950 border border-red-800 rounded-xl px-5 py-3 text-red-400 text-sm">
          {error}
        </div>
      )}

      {/* ── Loading spinner ────────────────────────────────────────────────── */}
      {loadingPreview && (
        <div className="flex items-center justify-center py-16">
          <div className="text-center">
            <div className="animate-spin h-10 w-10 border-4 border-purple-500 border-t-transparent rounded-full mx-auto mb-4" />
            <p className="text-gray-400">Computing report statistics…</p>
          </div>
        </div>
      )}

      {/* ── Preview section ────────────────────────────────────────────────── */}
      {preview && !loadingPreview && (
        <div className="space-y-6">
          {/* Generated timestamp + download button */}
          <div className="flex items-center justify-between">
            <p className="text-gray-500 text-xs">
              Generated: {preview.generated_at}
            </p>
            <button
              onClick={handleDownloadPdf}
              disabled={loadingPdf}
              className="px-6 py-2.5 bg-green-600 hover:bg-green-700 disabled:opacity-50 text-white text-sm font-bold rounded-lg transition-colors flex items-center gap-2"
            >
              {loadingPdf ? (
                <>
                  <div className="animate-spin h-4 w-4 border-2 border-white border-t-transparent rounded-full" />
                  Generating PDF…
                </>
              ) : (
                'Download PDF'
              )}
            </button>
          </div>

          {/* Filters applied */}
          <section className="bg-gray-900 border border-gray-800 rounded-xl p-6">
            <h3 className="text-white font-semibold mb-3">Filters Applied</h3>
            <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
              {Object.entries(preview.filters_applied || {}).map(([k, v]) => (
                <div key={k} className="flex items-center gap-2">
                  <span className="text-gray-500 text-xs">{k.replace(/_/g, ' ')}:</span>
                  <span className="text-gray-300 text-xs font-medium">{String(v)}</span>
                </div>
              ))}
            </div>
          </section>

          {/* ── Honeynet preview ───────────────────────────────────────────── */}
          {preview.honeynet && (
            <section className="bg-gray-900 border border-gray-800 rounded-xl p-6 space-y-5">
              <div>
                <h3 className="text-white font-semibold">Honeynet Attack Analysis</h3>
                <p className="text-gray-400 text-sm mt-0.5">Filtered honeypot event statistics</p>
              </div>

              {/* Big stat */}
              <div className="bg-purple-950 border border-purple-800 rounded-lg px-5 py-4 w-fit">
                <span className="text-3xl font-bold text-white">
                  {preview.honeynet.total_events.toLocaleString()}
                </span>
                <span className="text-purple-300 text-sm ml-2">total events</span>
              </div>

              {/* Summary paragraph */}
              <div className="bg-yellow-950/40 border-l-4 border-yellow-600 rounded-r-lg px-4 py-3">
                <p className="text-gray-300 text-sm leading-relaxed">{preview.honeynet.summary}</p>
              </div>

              {/* Tables grid */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div>
                  <h4 className="text-gray-300 text-sm font-medium mb-2">Top 5 Countries</h4>
                  <StatsTable rows={preview.honeynet.top_countries} col1="Country" col2="Events" />
                </div>
                <div>
                  <h4 className="text-gray-300 text-sm font-medium mb-2">Top 5 Protocols</h4>
                  <StatsTable rows={preview.honeynet.top_protocols} col1="Protocol" col2="Events" />
                </div>
              </div>
              <div>
                <h4 className="text-gray-300 text-sm font-medium mb-2">Top 5 Attack Types</h4>
                <StatsTable rows={preview.honeynet.top_attack_types} col1="Attack Type" col2="Events" />
              </div>
            </section>
          )}

          {/* ── Brute force preview ────────────────────────────────────────── */}
          {preview.brute_force && (
            <section className="bg-gray-900 border border-gray-800 rounded-xl p-6 space-y-5">
              <div>
                <h3 className="text-white font-semibold">Brute Force Intelligence</h3>
                <p className="text-gray-400 text-sm mt-0.5">Filtered credential attack statistics</p>
              </div>

              {/* Stat cards row */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
                  <div className="text-gray-400 text-xs uppercase tracking-wider mb-1">Total Attempts</div>
                  <div className="text-white text-2xl font-bold">{preview.brute_force.total_attempts.toLocaleString()}</div>
                </div>
                <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
                  <div className="text-gray-400 text-xs uppercase tracking-wider mb-1">Unique Usernames</div>
                  <div className="text-white text-2xl font-bold">{preview.brute_force.unique_usernames.toLocaleString()}</div>
                </div>
                <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
                  <div className="text-gray-400 text-xs uppercase tracking-wider mb-1">Unique Passwords</div>
                  <div className="text-white text-2xl font-bold">{preview.brute_force.unique_passwords.toLocaleString()}</div>
                </div>
                <div className="bg-red-950 border border-red-800 rounded-lg p-4">
                  <div className="text-red-300 text-xs uppercase tracking-wider mb-1">Default Creds</div>
                  <div className="text-red-400 text-2xl font-bold">{preview.brute_force.default_credential_pct}%</div>
                </div>
              </div>

              {/* Summary paragraph */}
              <div className="bg-yellow-950/40 border-l-4 border-yellow-600 rounded-r-lg px-4 py-3">
                <p className="text-gray-300 text-sm leading-relaxed">{preview.brute_force.summary}</p>
              </div>

              {/* Tables grid */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div>
                  <h4 className="text-gray-300 text-sm font-medium mb-2">Top 5 Usernames</h4>
                  <StatsTable rows={preview.brute_force.top_usernames} col1="Username" col2="Attempts" />
                </div>
                <div>
                  <h4 className="text-gray-300 text-sm font-medium mb-2">Top 5 Passwords</h4>
                  <StatsTable rows={preview.brute_force.top_passwords} col1="Password" col2="Attempts" />
                </div>
              </div>
              <div>
                <h4 className="text-gray-300 text-sm font-medium mb-2">Password Type Distribution</h4>
                <StatsTable rows={preview.brute_force.password_type_distribution} col1="Type" col2="Count" />
              </div>
            </section>
          )}

          {/* Bottom download button */}
          <div className="flex justify-center pt-2 pb-4">
            <button
              onClick={handleDownloadPdf}
              disabled={loadingPdf}
              className="px-8 py-3 bg-green-600 hover:bg-green-700 disabled:opacity-50 text-white text-sm font-bold rounded-lg transition-colors flex items-center gap-2"
            >
              {loadingPdf ? (
                <>
                  <div className="animate-spin h-4 w-4 border-2 border-white border-t-transparent rounded-full" />
                  Generating PDF…
                </>
              ) : (
                'Download PDF Report'
              )}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
