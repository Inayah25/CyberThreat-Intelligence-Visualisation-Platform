import { useState, useEffect } from 'react';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend, Cell,
  PieChart, Pie, LineChart, Line,
} from 'recharts';
import { bruteApi } from '../services/bruteApi';

const COLORS = [
  '#a855f7', '#8b5cf6', '#7c3aed', '#6d28d9', '#5b21b6',
  '#4c1d95', '#7c6dfa', '#6366f1', '#4f46e5', '#4338ca',
  '#a78bfa', '#c4b5fd', '#ddd6fe', '#fb7185', '#f43f5e',
];

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-xs">
      {label && <p className="text-white font-medium mb-1">{label}</p>}
      {payload.map((p) => (
        <p key={p.dataKey} className="text-purple-400">
          {p.value?.toLocaleString()} {p.name || 'count'}
        </p>
      ))}
    </div>
  );
};

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

export default function CredentialIntelligence() {
  const [summary, setSummary] = useState(null);
  const [topUsernames, setTopUsernames] = useState([]);
  const [topPasswords, setTopPasswords] = useState([]);
  const [topPairs, setTopPairs] = useState([]);
  const [passwordTypes, setPasswordTypes] = useState([]);
  const [passwordLengths, setPasswordLengths] = useState([]);
  const [topIps, setTopIps] = useState([]);
  const [timeline, setTimeline] = useState([]);

  useEffect(() => {
    Promise.all([
      bruteApi.summary(),
      bruteApi.topUsernames(),
      bruteApi.topPasswords(),
      bruteApi.topPairs(),
      bruteApi.passwordTypes(),
      bruteApi.passwordLengths(),
      bruteApi.topIps(),
      bruteApi.timeline(),
    ])
      .then(([sum, users, passes, pairs, types, lengths, ips, time]) => {
        setSummary(sum);
        setTopUsernames(users || []);
        setTopPasswords(passes || []);
        setTopPairs(pairs || []);
        setPasswordTypes(types || []);
        setPasswordLengths(lengths || []);
        setTopIps(ips || []);
        setTimeline(time || []);
      })
      .catch(console.error);
  }, []);

  if (!summary) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="text-center">
          <div className="animate-spin h-10 w-10 border-4 border-purple-500 border-t-transparent rounded-full mx-auto mb-4" />
          <p className="text-gray-400">Loading Credential Intelligence...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-bold text-white">Credential Intelligence</h1>
        <p className="text-gray-400 text-sm mt-1">SSH brute force attack analysis and credential patterns</p>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="Total Attempts" value={summary.totalAttempts?.toLocaleString()} />
        <StatCard label="Unique Usernames" value={summary.uniqueUsernames?.toLocaleString()} />
        <StatCard label="Unique Passwords" value={summary.uniquePasswords?.toLocaleString()} />
        <StatCard
          label="% Default Credentials"
          value={`${summary.defaultCredentialPct?.toFixed(2) ?? '0.00'}%`}
          accent
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <section className="bg-gray-900 border border-gray-800 rounded-xl p-6">
          <h2 className="text-white font-semibold mb-1">Top 20 Usernames</h2>
          <p className="text-gray-400 text-sm mb-4">Most targeted usernames</p>
          <div className="h-80">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={topUsernames} layout="vertical" margin={{ top: 0, right: 16, left: 0, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" horizontal={false} />
                <XAxis type="number" tick={{ fill: '#6b7280', fontSize: 10 }} tickLine={false} axisLine={false} />
                <YAxis
                  type="category"
                  dataKey="username"
                  tick={{ fill: '#9ca3af', fontSize: 10 }}
                  tickLine={false}
                  axisLine={false}
                  width={90}
                />
                <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(255,255,255,0.05)' }} />
                <Bar dataKey="count" name="Attempts" radius={[0, 4, 4, 0]}>
                  {topUsernames.map((_, i) => (
                    <Cell key={i} fill={COLORS[i % COLORS.length]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </section>

        <section className="bg-gray-900 border border-gray-800 rounded-xl p-6">
          <h2 className="text-white font-semibold mb-1">Top 20 Passwords</h2>
          <p className="text-gray-400 text-sm mb-4">Most common passwords tried</p>
          <div className="h-80">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={topPasswords} layout="vertical" margin={{ top: 0, right: 16, left: 0, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" horizontal={false} />
                <XAxis type="number" tick={{ fill: '#6b7280', fontSize: 10 }} tickLine={false} axisLine={false} />
                <YAxis
                  type="category"
                  dataKey="password"
                  tick={{ fill: '#9ca3af', fontSize: 10 }}
                  tickLine={false}
                  axisLine={false}
                  width={90}
                />
                <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(255,255,255,0.05)' }} />
                <Bar dataKey="count" name="Attempts" radius={[0, 4, 4, 0]}>
                  {topPasswords.map((_, i) => (
                    <Cell key={i} fill={COLORS[i % COLORS.length]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </section>
      </div>

      <section className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <div className="p-6 border-b border-gray-800">
          <h2 className="text-white font-semibold">Top 20 Credential Pairs</h2>
          <p className="text-gray-400 text-sm">Most common username + password combinations</p>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="bg-gray-800/50 text-gray-400">
                <th className="px-3 py-2.5 text-left font-medium">Rank</th>
                <th className="px-3 py-2.5 text-left font-medium">Username</th>
                <th className="px-3 py-2.5 text-left font-medium">Password</th>
                <th className="px-3 py-2.5 text-right font-medium">Attempts</th>
              </tr>
            </thead>
            <tbody>
              {topPairs.length === 0 ? (
                <tr>
                  <td colSpan={4} className="px-3 py-12 text-center text-gray-500">
                    No credential pairs found
                  </td>
                </tr>
              ) : (
                topPairs.map((pair, i) => (
                  <tr
                    key={i}
                    className="border-t border-gray-800 hover:bg-gray-800/40 transition-colors"
                  >
                    <td className="px-3 py-3 text-gray-500 w-12">
                      <span className="inline-flex items-center justify-center h-5 w-5 rounded-full bg-gray-800 text-xs">
                        {i + 1}
                      </span>
                    </td>
                    <td className="px-3 py-3 text-gray-300 font-mono">{pair.username}</td>
                    <td className="px-3 py-3 text-gray-300 font-mono">{pair.password}</td>
                    <td className="px-3 py-3 text-right text-purple-400 font-semibold">
                      {pair.count.toLocaleString()}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <section className="bg-gray-900 border border-gray-800 rounded-xl p-6">
          <h2 className="text-white font-semibold mb-1">Password Type Distribution</h2>
          <p className="text-gray-400 text-sm mb-4">Character composition of passwords</p>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={passwordTypes}
                  dataKey="count"
                  nameKey="type"
                  cx="50%"
                  cy="50%"
                  outerRadius={80}
                  innerRadius={40}
                  label={({ type, percent }) => `${type} ${(percent * 100).toFixed(0)}%`}
                  labelLine={false}
                >
                  {passwordTypes.map((_, i) => (
                    <Cell key={i} fill={COLORS[i % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip content={<CustomTooltip />} />
                <Legend wrapperStyle={{ fontSize: 12, color: '#9ca3af' }} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </section>

        <section className="bg-gray-900 border border-gray-800 rounded-xl p-6">
          <h2 className="text-white font-semibold mb-1">Password Length Distribution</h2>
          <p className="text-gray-400 text-sm mb-4">Attempts by password length</p>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={passwordLengths} margin={{ top: 0, right: 16, left: 0, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
                <XAxis
                  dataKey="length"
                  tick={{ fill: '#6b7280', fontSize: 10 }}
                  tickLine={false}
                  axisLine={false}
                  label={{ value: 'Length', position: 'insideBottom', offset: -5, fill: '#6b7280', fontSize: 10 }}
                />
                <YAxis tick={{ fill: '#6b7280', fontSize: 10 }} tickLine={false} axisLine={false} />
                <Tooltip content={<CustomTooltip />} />
                <Bar dataKey="count" name="Attempts" fill="#a855f7" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </section>
      </div>

      <section className="bg-gray-900 border border-gray-800 rounded-xl p-6">
        <h2 className="text-white font-semibold mb-1">Top 20 Attacking IPs</h2>
        <p className="text-gray-400 text-sm mb-4">Source IPs with most brute force attempts</p>
        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={topIps} layout="vertical" margin={{ top: 0, right: 16, left: 0, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" horizontal={false} />
              <XAxis type="number" tick={{ fill: '#6b7280', fontSize: 10 }} tickLine={false} axisLine={false} />
              <YAxis
                type="category"
                dataKey="ip"
                tick={{ fill: '#9ca3af', fontSize: 9 }}
                tickLine={false}
                axisLine={false}
                width={110}
              />
              <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(255,255,255,0.05)' }} />
              <Bar dataKey="count" name="Attempts" radius={[0, 4, 4, 0]}>
                {topIps.map((_, i) => (
                  <Cell key={i} fill={COLORS[i % COLORS.length]} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </section>

      <section className="bg-gray-900 border border-gray-800 rounded-xl p-6">
        <h2 className="text-white font-semibold mb-1">Attack Timeline</h2>
        <p className="text-gray-400 text-sm mb-4">Brute force attempts over time</p>
        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={timeline} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
              <XAxis
                dataKey="date"
                tick={{ fill: '#6b7280', fontSize: 10 }}
                tickLine={false}
                axisLine={false}
                interval={Math.ceil(timeline.length / 10)}
              />
              <YAxis tick={{ fill: '#6b7280', fontSize: 10 }} tickLine={false} axisLine={false} />
              <Tooltip content={<CustomTooltip />} />
              <Legend wrapperStyle={{ fontSize: 12, color: '#9ca3af' }} />
              <Line
                type="monotone"
                dataKey="count"
                stroke="#a855f7"
                strokeWidth={2}
                dot={false}
                name="Attempts"
                activeDot={{ r: 4, fill: '#a855f7' }}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </section>
    </div>
  );
}
