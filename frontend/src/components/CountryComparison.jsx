import { useState, useEffect } from 'react';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  LineChart, Line, Cell,
} from 'recharts';
import { api } from '../services/api';

const COLORS_A = ['#a855f7', '#8b5cf6', '#7c3aed', '#6d28d9', '#5b21b6'];
const COLORS_B = ['#f43f5e', '#fb7185', '#e11d48', '#be123c', '#9f1239'];

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-xs">
      {label != null && <p className="text-white font-medium mb-1">{label}</p>}
      {payload.map((p, i) => (
        <p key={i} className="text-purple-400">
          {p.value?.toLocaleString()} {p.name || 'count'}
        </p>
      ))}
    </div>
  );
};

function NoData({ country }) {
  return (
    <div className="flex items-center justify-center h-40 text-gray-500 text-sm">
      No data available for {country}
    </div>
  );
}

function HorizontalBarSection({ title, data, dataKey, nameKey, colors }) {
  return (
    <section className="bg-gray-900 border border-gray-800 rounded-xl p-5">
      <h3 className="text-white font-semibold text-sm mb-3">{title}</h3>
      <div className="h-52">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} layout="vertical" margin={{ top: 0, right: 12, left: 0, bottom: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" horizontal={false} />
            <XAxis type="number" tick={{ fill: '#6b7280', fontSize: 10 }} tickLine={false} axisLine={false} />
            <YAxis
              type="category"
              dataKey={nameKey}
              tick={{ fill: '#9ca3af', fontSize: 10 }}
              tickLine={false}
              axisLine={false}
              width={80}
            />
            <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(255,255,255,0.05)' }} />
            <Bar dataKey={dataKey} name="Count" radius={[0, 4, 4, 0]}>
              {data.map((_, i) => (
                <Cell key={i} fill={colors[i % colors.length]} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </section>
  );
}

function ComparisonRow({ label, val1, val2, fmt }) {
  const format = fmt || (v => v);
  const v1 = typeof val1 === 'number' ? val1 : 0;
  const v2 = typeof val2 === 'number' ? val2 : 0;
  const winner = v1 > v2 ? 1 : v2 > v1 ? 2 : 0;

  return (
    <tr className="border-b border-gray-800 last:border-0">
      <td className="px-4 py-3 text-gray-400 text-sm">{label}</td>
      <td className={`px-4 py-3 text-sm text-right ${winner === 1 ? 'text-purple-400 font-semibold' : 'text-gray-300'}`}>
        {format(val1)}
        {winner === 1 && <span className="ml-2 text-[10px] bg-purple-600/30 text-purple-300 px-1.5 py-0.5 rounded">Higher</span>}
      </td>
      <td className={`px-4 py-3 text-sm text-right ${winner === 2 ? 'text-rose-400 font-semibold' : 'text-gray-300'}`}>
        {format(val2)}
        {winner === 2 && <span className="ml-2 text-[10px] bg-rose-600/30 text-rose-300 px-1.5 py-0.5 rounded">Higher</span>}
      </td>
    </tr>
  );
}

export default function CountryComparison() {
  const [countries, setCountries] = useState([]);
  const [sel1, setSel1] = useState('China');
  const [sel2, setSel2] = useState('Russia');
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchData = (c1, c2) => {
    setLoading(true);
    setError(null);
    api.compareCountries(c1, c2)
      .then(d => {
        setData(d);
        if (d.available_countries) setCountries(d.available_countries);
        setLoading(false);
      })
      .catch(err => {
        setError(err.message);
        setLoading(false);
      });
  };

  useEffect(() => { fetchData(sel1, sel2); }, []);

  const handleCompare = () => {
    if (sel1 === sel2) {
      setError('Select two different countries');
      return;
    }
    fetchData(sel1, sel2);
  };

  const nightCount = (hourly) => {
    if (!hourly?.length) return 0;
    return hourly
      .filter(h => h.hour >= 22 || h.hour <= 5)
      .reduce((s, h) => s + h.count, 0);
  };

  const dayCount = (hourly) => {
    if (!hourly?.length) return 0;
    return hourly
      .filter(h => h.hour >= 8 && h.hour <= 18)
      .reduce((s, h) => s + h.count, 0);
  };

  const dominantProtocol = (stats) => {
    if (!stats?.top_protocols?.length) return { name: '—', pct: 0 };
    const top = stats.top_protocols[0];
    const pct = stats.total_attacks > 0 ? ((top.count / stats.total_attacks) * 100).toFixed(1) : 0;
    return { name: top.protocol, pct };
  };

  if (loading && !data) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="text-center">
          <div className="animate-spin h-10 w-10 border-4 border-purple-500 border-t-transparent rounded-full mx-auto mb-4" />
          <p className="text-gray-400">Loading Country Comparison...</p>
        </div>
      </div>
    );
  }

  const c1 = data?.country1;
  const c2 = data?.country2;

  return (
    <div className="space-y-8">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white">Country Comparison</h1>
        <p className="text-gray-400 text-sm mt-1">Compare attack patterns between two countries side by side</p>
      </div>

      {/* Selection Panel */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
        <div className="flex flex-wrap items-end gap-4">
          <div className="flex-1 min-w-[180px]">
            <label className="block text-gray-400 text-xs mb-1.5">Country 1</label>
            <select
              value={sel1}
              onChange={e => setSel1(e.target.value)}
              className="w-full bg-gray-800 border border-gray-700 text-gray-300 text-sm rounded-lg px-3 py-2 focus:outline-none focus:border-purple-500"
            >
              {countries.map(c => <option key={c} value={c}>{c}</option>)}
            </select>
          </div>
          <div className="flex-1 min-w-[180px]">
            <label className="block text-gray-400 text-xs mb-1.5">Country 2</label>
            <select
              value={sel2}
              onChange={e => setSel2(e.target.value)}
              className="w-full bg-gray-800 border border-gray-700 text-gray-300 text-sm rounded-lg px-3 py-2 focus:outline-none focus:border-purple-500"
            >
              {countries.map(c => <option key={c} value={c}>{c}</option>)}
            </select>
          </div>
          <button
            onClick={handleCompare}
            disabled={loading}
            className="px-6 py-2 bg-purple-600 hover:bg-purple-700 disabled:opacity-50 text-white text-sm font-medium rounded-lg transition-colors"
          >
            {loading ? 'Loading...' : 'Compare'}
          </button>
        </div>
        {error && <p className="text-red-400 text-sm mt-3">{error}</p>}
        {sel1 === sel2 && <p className="text-amber-400 text-sm mt-3">Select two different countries for comparison</p>}
      </div>

      {/* Results */}
      {data && (
        <>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Country 1 Column */}
            <div className="space-y-4">
              <div className="flex items-center gap-2 mb-2">
                <div className="h-3 w-3 rounded-full bg-purple-500" />
                <h2 className="text-lg font-bold text-white">{c1?.name}</h2>
              </div>

              {c1?.no_data ? <NoData country={c1.name} /> : (
                <>
                  {/* Total Attacks */}
                  <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                    <span className="text-gray-400 text-xs uppercase tracking-wider">Total Attacks</span>
                    <p className="text-3xl font-bold text-purple-400 mt-1">{c1.total_attacks?.toLocaleString()}</p>
                    <p className="text-gray-500 text-xs mt-1">
                      {c1.first_seen && `${new Date(c1.first_seen).toLocaleDateString()} — ${new Date(c1.last_seen).toLocaleDateString()}`}
                    </p>
                  </div>

                  <HorizontalBarSection title="Attack Types" data={c1.attack_types} dataKey="count" nameKey="type" colors={COLORS_A} />
                  <HorizontalBarSection title="Top 5 Protocols" data={c1.top_protocols} dataKey="count" nameKey="protocol" colors={COLORS_A} />
                  <HorizontalBarSection title="Top 5 Targeted Ports" data={c1.top_ports} dataKey="count" nameKey="port" colors={COLORS_A} />

                  {/* Hourly Distribution */}
                  <section className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                    <h3 className="text-white font-semibold text-sm mb-3">Time of Day Activity</h3>
                    <div className="h-52">
                      <ResponsiveContainer width="100%" height="100%">
                        <LineChart data={c1.hourly_distribution} margin={{ top: 5, right: 12, left: 0, bottom: 0 }}>
                          <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
                          <XAxis dataKey="hour" tick={{ fill: '#6b7280', fontSize: 10 }} tickLine={false} axisLine={false} />
                          <YAxis tick={{ fill: '#6b7280', fontSize: 10 }} tickLine={false} axisLine={false} />
                          <Tooltip content={<CustomTooltip />} />
                          <Line type="monotone" dataKey="count" stroke="#a855f7" strokeWidth={2} dot={false} />
                        </LineChart>
                      </ResponsiveContainer>
                    </div>
                  </section>

                  {/* Daily Distribution */}
                  <section className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                    <h3 className="text-white font-semibold text-sm mb-3">Day of Week Activity</h3>
                    <div className="h-52">
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={c1.daily_distribution} margin={{ top: 5, right: 12, left: 0, bottom: 0 }}>
                          <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
                          <XAxis dataKey="day" tick={{ fill: '#6b7280', fontSize: 9 }} tickLine={false} axisLine={false} />
                          <YAxis tick={{ fill: '#6b7280', fontSize: 10 }} tickLine={false} axisLine={false} />
                          <Tooltip content={<CustomTooltip />} />
                          <Bar dataKey="count" name="Attacks" radius={[4, 4, 0, 0]}>
                            {c1.daily_distribution.map((_, i) => (
                              <Cell key={i} fill={COLORS_A[i % COLORS_A.length]} />
                            ))}
                          </Bar>
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                  </section>
                </>
              )}
            </div>

            {/* Country 2 Column */}
            <div className="space-y-4">
              <div className="flex items-center gap-2 mb-2">
                <div className="h-3 w-3 rounded-full bg-rose-500" />
                <h2 className="text-lg font-bold text-white">{c2?.name}</h2>
              </div>

              {c2?.no_data ? <NoData country={c2.name} /> : (
                <>
                  <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                    <span className="text-gray-400 text-xs uppercase tracking-wider">Total Attacks</span>
                    <p className="text-3xl font-bold text-rose-400 mt-1">{c2.total_attacks?.toLocaleString()}</p>
                    <p className="text-gray-500 text-xs mt-1">
                      {c2.first_seen && `${new Date(c2.first_seen).toLocaleDateString()} — ${new Date(c2.last_seen).toLocaleDateString()}`}
                    </p>
                  </div>

                  <HorizontalBarSection title="Attack Types" data={c2.attack_types} dataKey="count" nameKey="type" colors={COLORS_B} />
                  <HorizontalBarSection title="Top 5 Protocols" data={c2.top_protocols} dataKey="count" nameKey="protocol" colors={COLORS_B} />
                  <HorizontalBarSection title="Top 5 Targeted Ports" data={c2.top_ports} dataKey="count" nameKey="port" colors={COLORS_B} />

                  <section className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                    <h3 className="text-white font-semibold text-sm mb-3">Time of Day Activity</h3>
                    <div className="h-52">
                      <ResponsiveContainer width="100%" height="100%">
                        <LineChart data={c2.hourly_distribution} margin={{ top: 5, right: 12, left: 0, bottom: 0 }}>
                          <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
                          <XAxis dataKey="hour" tick={{ fill: '#6b7280', fontSize: 10 }} tickLine={false} axisLine={false} />
                          <YAxis tick={{ fill: '#6b7280', fontSize: 10 }} tickLine={false} axisLine={false} />
                          <Tooltip content={<CustomTooltip />} />
                          <Line type="monotone" dataKey="count" stroke="#f43f5e" strokeWidth={2} dot={false} />
                        </LineChart>
                      </ResponsiveContainer>
                    </div>
                  </section>

                  <section className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                    <h3 className="text-white font-semibold text-sm mb-3">Day of Week Activity</h3>
                    <div className="h-52">
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={c2.daily_distribution} margin={{ top: 5, right: 12, left: 0, bottom: 0 }}>
                          <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
                          <XAxis dataKey="day" tick={{ fill: '#6b7280', fontSize: 9 }} tickLine={false} axisLine={false} />
                          <YAxis tick={{ fill: '#6b7280', fontSize: 10 }} tickLine={false} axisLine={false} />
                          <Tooltip content={<CustomTooltip />} />
                          <Bar dataKey="count" name="Attacks" radius={[4, 4, 0, 0]}>
                            {c2.daily_distribution.map((_, i) => (
                              <Cell key={i} fill={COLORS_B[i % COLORS_B.length]} />
                            ))}
                          </Bar>
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                  </section>
                </>
              )}
            </div>
          </div>

          {/* Head to Head Summary */}
          {c1 && c2 && !c1.no_data && !c2.no_data && (
            <section className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
              <div className="p-6 border-b border-gray-800">
                <h2 className="text-white font-semibold">Head to Head Summary</h2>
                <p className="text-gray-400 text-sm">Direct comparison of key metrics</p>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="bg-gray-800/50 text-gray-400 text-xs">
                      <th className="px-4 py-2.5 text-left font-medium">Metric</th>
                      <th className="px-4 py-2.5 text-right font-medium">
                        <span className="inline-flex items-center gap-1.5">
                          <span className="h-2 w-2 rounded-full bg-purple-500" />
                          {c1.name}
                        </span>
                      </th>
                      <th className="px-4 py-2.5 text-right font-medium">
                        <span className="inline-flex items-center gap-1.5">
                          <span className="h-2 w-2 rounded-full bg-rose-500" />
                          {c2.name}
                        </span>
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    <ComparisonRow
                      label="Total Attacks"
                      val1={c1.total_attacks}
                      val2={c2.total_attacks}
                      fmt={v => v?.toLocaleString()}
                    />
                    <ComparisonRow
                      label="Unique Attack Types"
                      val1={c1.attack_types?.length}
                      val2={c2.attack_types?.length}
                    />
                    <ComparisonRow
                      label="Night Activity (22:00–05:00)"
                      val1={nightCount(c1.hourly_distribution)}
                      val2={nightCount(c2.hourly_distribution)}
                      fmt={v => v?.toLocaleString()}
                    />
                    <ComparisonRow
                      label="Day Activity (08:00–18:00)"
                      val1={dayCount(c1.hourly_distribution)}
                      val2={dayCount(c2.hourly_distribution)}
                      fmt={v => v?.toLocaleString()}
                    />
                    <tr className="border-b border-gray-800">
                      <td className="px-4 py-3 text-gray-400 text-sm">Dominant Protocol</td>
                      <td className="px-4 py-3 text-sm text-right text-gray-300">
                        {dominantProtocol(c1).name} ({dominantProtocol(c1).pct}%)
                      </td>
                      <td className="px-4 py-3 text-sm text-right text-gray-300">
                        {dominantProtocol(c2).name} ({dominantProtocol(c2).pct}%)
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </section>
          )}
        </>
      )}
    </div>
  );
}
