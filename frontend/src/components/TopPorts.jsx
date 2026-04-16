import { useState, useEffect } from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { api } from '../services/api';

const CustomTooltip = ({ active, payload }) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-xs">
      <p className="text-white font-medium">Port {payload[0].payload.port}</p>
      <p className="text-purple-400">{payload[0].value.toLocaleString()} attacks</p>
    </div>
  );
};

export default function TopPorts() {
  const [data, setData] = useState([]);

  useEffect(() => {
    api.ports(12).then(res => setData(res.data || [])).catch(console.error);
  }, []);

  return (
    <section className="bg-gray-900 border border-gray-800 rounded-xl p-6">
      <h2 className="text-white font-semibold mb-1">Top Targeted Ports</h2>
      <p className="text-gray-400 text-sm mb-6">Most frequently attacked network ports</p>
      <div className="h-64">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} margin={{ top: 0, right: 16, left: -10, bottom: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
            <XAxis
              dataKey="port"
              tick={{ fill: '#6b7280', fontSize: 10 }}
              tickLine={false}
              axisLine={false}
            />
            <YAxis tick={{ fill: '#6b7280', fontSize: 10 }} tickLine={false} axisLine={false} />
            <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(255,255,255,0.05)' }} />
            <Bar dataKey="count" fill="#6366f1" radius={[4, 4, 0, 0]} name="Attacks" />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </section>
  );
}
