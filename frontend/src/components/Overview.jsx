import { useState, useEffect } from 'react';
import { api } from '../services/api';

function StatCard({ label, value, sub, accent }) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 flex flex-col gap-1">
      <span className="text-gray-400 text-xs uppercase tracking-wider">{label}</span>
      <span className={`text-3xl font-bold ${accent ? 'text-purple-400' : 'text-white'}`}>
        {value ?? '—'}
      </span>
      {sub && <span className="text-gray-500 text-xs">{sub}</span>}
    </div>
  );
}

export default function Overview() {
  const [data, setData] = useState(null);

  useEffect(() => {
    api.overview().then(setData).catch(console.error);
  }, []);

  if (!data) {
    return (
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[...Array(4)].map((_, i) => (
          <div key={i} className="bg-gray-900 border border-gray-800 rounded-xl p-5 animate-pulse h-24" />
        ))}
      </div>
    );
  }

  const topCountry = Object.entries(data.topSourceCountry || {}).map(([k, v]) => ({ country: k, count: v }));

  return (
    <section>
      <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-4">Overview</h2>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="Total Events" value={data.totalEvents?.toLocaleString()} />
        <StatCard label="Unique Source IPs" value={data.uniqueSourceIPs?.toLocaleString()} />
        <StatCard label="Countries" value={data.countries?.toLocaleString()} />
        <StatCard
          label="Top Source Country"
          value={topCountry[0]?.country || '—'}
          sub={topCountry[0] ? `${topCountry[0].count.toLocaleString()} attacks` : null}
          accent
        />
        <StatCard label="Unique Dest IPs" value={data.uniqueDestinationIPs?.toLocaleString()} />
        <StatCard label="Protocols" value={data.protocols?.toLocaleString()} />
        <StatCard label="Attack Types" value={data.attackTypes?.toLocaleString()} />
        <StatCard
          label="Date Range"
          value={data.dateRange?.start ? new Date(data.dateRange.start).toLocaleDateString() : '—'}
          sub={data.dateRange?.start && data.dateRange?.end
            ? `to ${new Date(data.dateRange.end).toLocaleDateString()}`
            : null}
        />
      </div>
    </section>
  );
}
