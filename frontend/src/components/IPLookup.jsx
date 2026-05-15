import { useState, useRef } from 'react';
import { api } from '../services/api';

const EXAMPLE_IPS = [
  { ip: '23.175.48.211', note: 'Top attacker in local dataset' },
  { ip: '5.196.115.163', note: 'High-frequency source IP' },
  { ip: '128.241.230.60', note: 'Frequent local honeypot visitor' },
];

function scoreColor(score) {
  if (score <= 25) return { text: 'text-green-400', bg: 'bg-green-400/10', border: 'border-green-400/30', label: 'CLEAN', ring: '#4ade80' };
  if (score <= 50) return { text: 'text-yellow-400', bg: 'bg-yellow-400/10', border: 'border-yellow-400/30', label: 'SUSPICIOUS', ring: '#facc15' };
  if (score <= 75) return { text: 'text-orange-400', bg: 'bg-orange-400/10', border: 'border-orange-400/30', label: 'DANGEROUS', ring: '#fb923c' };
  return { text: 'text-red-400', bg: 'bg-red-400/10', border: 'border-red-400/30', label: 'CRITICAL', ring: '#f87171' };
}

function DetailRow({ label, value }) {
  if (value == null || value === '') return null;
  return (
    <div className="flex justify-between items-start gap-4 py-2 border-b border-gray-800 last:border-0">
      <span className="text-gray-400 text-xs uppercase tracking-wider shrink-0">{label}</span>
      <span className="text-gray-200 text-sm text-right">{String(value)}</span>
    </div>
  );
}

function GlobalReputationCard({ data }) {
  const score = data.abuse_confidence_score;
  const style = scoreColor(score);

  return (
    <section className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
      <div className="p-6 border-b border-gray-800">
        <h2 className="text-white font-semibold">Global Reputation</h2>
        <p className="text-gray-400 text-sm">Powered by AbuseIPDB</p>
      </div>

      <div className="p-6">
        {/* Score + Verdict */}
        {data.total_reports === 0 ? (
          <div className="flex items-center gap-3 mb-6 p-4 bg-green-400/10 border border-green-400/30 rounded-xl">
            <span className="text-2xl">✓</span>
            <div>
              <p className="text-green-400 font-semibold">No abuse reports found globally</p>
              <p className="text-gray-400 text-sm">This IP has no recorded abuse reports in the last 90 days.</p>
            </div>
          </div>
        ) : (
          <div className={`flex items-center gap-6 mb-6 p-4 rounded-xl border ${style.bg} ${style.border}`}>
            <div className="text-center">
              <div className={`text-5xl font-black tabular-nums ${style.text}`}>{score}</div>
              <div className="text-gray-400 text-xs mt-1">out of 100</div>
            </div>
            <div>
              <div className={`text-xs font-bold tracking-widest px-2.5 py-1 rounded inline-block mb-2 ${style.bg} ${style.text} border ${style.border}`}>
                {style.label}
              </div>
              <p className="text-gray-300 text-sm">Abuse Confidence Score</p>
              <p className="text-gray-400 text-xs mt-0.5">{data.total_reports.toLocaleString()} global abuse reports</p>
            </div>
          </div>
        )}

        {/* Details */}
        <div className="space-y-0">
          <DetailRow label="IP Address" value={data.ip_address} />
          <DetailRow label="Country" value={data.country_name ? `${data.country_name} (${data.country_code})` : data.country_code} />
          <DetailRow label="ISP" value={data.isp} />
          <DetailRow label="Domain" value={data.domain} />
          <DetailRow label="Usage Type" value={data.usage_type} />
          <DetailRow label="Total Reports" value={data.total_reports?.toLocaleString()} />
          <DetailRow
            label="Last Reported"
            value={data.last_reported_at ? new Date(data.last_reported_at).toLocaleString() : 'Never'}
          />
          <DetailRow label="Whitelisted" value={data.is_whitelisted ? 'Yes' : 'No'} />
        </div>
      </div>
    </section>
  );
}

function LocalObservationsCard({ data }) {
  if (!data.found_locally) {
    return (
      <section className="bg-gray-900 border border-gray-800 rounded-xl p-6">
        <div className="flex items-center gap-3 text-gray-400">
          <span className="text-xl">✓</span>
          <div>
            <p className="text-gray-300 font-medium">Not observed in local honeypot dataset</p>
            <p className="text-gray-500 text-sm">This IP has no recorded activity in the monitored network.</p>
          </div>
        </div>
      </section>
    );
  }

  return (
    <section className="bg-gray-900 border border-amber-500/30 rounded-xl overflow-hidden">
      <div className="p-6 border-b border-amber-500/30 bg-amber-500/5">
        <div className="flex items-center gap-2">
          <span className="text-amber-400 text-lg">⚠</span>
          <h2 className="text-amber-400 font-semibold">Observed in Local Honeypot Data</h2>
        </div>
        <p className="text-gray-400 text-sm mt-1">This IP was seen attacking our monitored infrastructure.</p>
      </div>
      <div className="p-6 space-y-0">
        <DetailRow label="Times Observed" value={data.local_attack_count?.toLocaleString()} />
        <DetailRow label="Attack Types" value={data.local_attack_types?.join(', ') || '—'} />
        <DetailRow label="Protocols Used" value={data.local_protocols?.join(', ') || '—'} />
        <DetailRow label="Country (Local)" value={data.local_country} />
        <DetailRow
          label="First Seen"
          value={data.local_first_seen ? new Date(data.local_first_seen).toLocaleString() : null}
        />
        <DetailRow
          label="Last Seen"
          value={data.local_last_seen ? new Date(data.local_last_seen).toLocaleString() : null}
        />
      </div>
    </section>
  );
}

function EmptyState({ onExample }) {
  return (
    <section className="bg-gray-900 border border-gray-800 rounded-xl p-8 text-center">
      <div className="text-4xl mb-4">🔍</div>
      <h2 className="text-white font-semibold text-lg mb-2">Search any IP address</h2>
      <p className="text-gray-400 text-sm max-w-md mx-auto mb-6">
        Cross-reference against AbuseIPDB's global threat database and our local honeypot observations.
      </p>
      <div className="text-left max-w-sm mx-auto">
        <p className="text-gray-500 text-xs uppercase tracking-wider mb-3">Example IPs from local dataset</p>
        <div className="space-y-2">
          {EXAMPLE_IPS.map(({ ip, note }) => (
            <button
              key={ip}
              onClick={() => onExample(ip)}
              className="w-full flex items-center justify-between px-4 py-2.5 bg-gray-800 hover:bg-gray-700 border border-gray-700 rounded-lg transition-colors group"
            >
              <span className="text-purple-400 font-mono text-sm">{ip}</span>
              <span className="text-gray-500 text-xs group-hover:text-gray-400">{note}</span>
            </button>
          ))}
        </div>
      </div>
    </section>
  );
}

const IP_RE = /^(\d{1,3}\.){3}\d{1,3}$/;

export default function IPLookup() {
  const [inputVal, setInputVal] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [validationErr, setValidationErr] = useState(null);
  const inputRef = useRef(null);

  const doLookup = (ip) => {
    const trimmed = ip.trim();
    if (!trimmed) {
      setValidationErr('Please enter a valid IP address');
      return;
    }
    if (!IP_RE.test(trimmed)) {
      setValidationErr('Please enter a valid IP address');
      return;
    }
    setValidationErr(null);
    setError(null);
    setResult(null);
    setLoading(true);
    api.ipLookup(trimmed)
      .then(data => {
        setResult(data);
        setLoading(false);
      })
      .catch(err => {
        setError(err.message);
        setLoading(false);
      });
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter') doLookup(inputVal);
  };

  const handleExample = (ip) => {
    setInputVal(ip);
    doLookup(ip);
  };

  return (
    <div className="space-y-8">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white">IP Reputation Lookup</h1>
        <p className="text-gray-400 text-sm mt-1">
          Check any IP address against global threat intelligence and our local honeypot observations
        </p>
      </div>

      {/* Search Panel */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
        <div className="flex gap-3">
          <div className="flex-1">
            <input
              ref={inputRef}
              type="text"
              value={inputVal}
              onChange={e => { setInputVal(e.target.value); setValidationErr(null); }}
              onKeyDown={handleKeyDown}
              placeholder="Enter IP address e.g. 192.168.1.1"
              className="w-full bg-gray-800 border border-gray-700 text-gray-200 text-sm rounded-lg px-4 py-2.5 focus:outline-none focus:border-purple-500 placeholder-gray-600"
            />
          </div>
          <button
            onClick={() => doLookup(inputVal)}
            disabled={loading}
            className="px-6 py-2.5 bg-purple-600 hover:bg-purple-700 disabled:opacity-50 text-white text-sm font-medium rounded-lg transition-colors flex items-center gap-2 shrink-0"
          >
            {loading ? (
              <>
                <span className="h-4 w-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                Looking up...
              </>
            ) : (
              'Look Up'
            )}
          </button>
        </div>
        {validationErr && <p className="text-red-400 text-sm mt-2">{validationErr}</p>}
      </div>

      {/* Error State */}
      {error && (
        <section className="bg-red-500/10 border border-red-500/30 rounded-xl p-6">
          <div className="flex items-start gap-3">
            <span className="text-red-400 text-xl shrink-0">✗</span>
            <div>
              <p className="text-red-400 font-semibold">Lookup Failed</p>
              <p className="text-gray-400 text-sm mt-1">{error}</p>
            </div>
          </div>
        </section>
      )}

      {/* Empty State */}
      {!result && !error && !loading && (
        <EmptyState onExample={handleExample} />
      )}

      {/* Results */}
      {result && (
        <div className="space-y-4">
          <GlobalReputationCard data={result.global_reputation} />
          <LocalObservationsCard data={result.local_observations} />
        </div>
      )}
    </div>
  );
}
