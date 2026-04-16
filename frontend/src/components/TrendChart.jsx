import { useState, useEffect } from 'react';
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend,
} from 'recharts';
import { api } from '../services/api';

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-xs">
      <p className="text-gray-300 mb-1">{label}</p>
      {payload.map((p) => (
        <p key={p.dataKey} className="text-purple-400 font-semibold">
          {p.value.toLocaleString()} events
        </p>
      ))}
    </div>
  );
};

export default function TrendChart() {
  const [data, setData] = useState([]);
  const [groupBy, setGroupBy] = useState('day');

  useEffect(() => {
    api.trends(groupBy).then(res => {
      setData(res.data || []);
    }).catch(console.error);
  }, [groupBy]);

  return (
    <section className="bg-gray-900 border border-gray-800 rounded-xl p-6">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-white font-semibold">Event Trends</h2>
          <p className="text-gray-400 text-sm">Attack volume over time</p>
        </div>
        <div className="flex gap-1 bg-gray-800 rounded-lg p-1">
          {['day', 'hour'].map(gb => (
            <button
              key={gb}
              onClick={() => setGroupBy(gb)}
              className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
                groupBy === gb
                  ? 'bg-purple-600 text-white'
                  : 'text-gray-400 hover:text-white'
              }`}
            >
              {gb === 'day' ? 'Daily' : 'Hourly'}
            </button>
          ))}
        </div>
      </div>

      <div className="h-64">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={data} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
            <XAxis
              dataKey="time_group"
              tick={{ fill: '#6b7280', fontSize: 10 }}
              tickLine={false}
              axisLine={false}
              interval={groupBy === 'hour' ? 11 : 6}
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
              name="Events"
              activeDot={{ r: 4, fill: '#a855f7' }}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </section>
  );
}
