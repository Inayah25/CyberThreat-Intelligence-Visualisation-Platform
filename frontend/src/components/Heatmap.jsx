import { useState, useEffect } from 'react';
import { api } from '../services/api';

export default function Heatmap() {
  const [payload, setPayload] = useState({ hours: [], days: [], data: [] });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.heatmap()
      .then(res => {
        setPayload(res);
        setLoading(false);
      })
      .catch(err => {
        console.error(err);
        setLoading(false);
      });
  }, []);

  if (loading) {
    return (
      <section className="bg-gray-900 border border-gray-800 rounded-xl p-6">
        <div className="animate-pulse h-48 bg-gray-800 rounded" />
      </section>
    );
  }

  const { hours, days, data } = payload;
  const max = Math.max(...data.flatMap(row => hours.map(h => row[h] || 0)), 1);

  const getColor = (val) => {
    if (!val || val === 0) return 'bg-gray-850';
    const intensity = val / max;
    const lightness = Math.round(20 + intensity * 60);
    return `bg-purple-${Math.max(900 - Math.round(intensity * 700), 100)}`;
  };

  return (
    <section className="bg-gray-900 border border-gray-800 rounded-xl p-6">
      <h2 className="text-white font-semibold mb-1">Attack Heatmap</h2>
      <p className="text-gray-400 text-sm mb-6">Hour of day vs day of week -: highlighted = more attacks</p>
      <div className="overflow-x-auto">
        <div className="inline-block min-w-full">
          {/* Header row */}
          <div className="flex gap-1 mb-1 pl-10">
            {hours.map(h => (
              <div key={h} className="w-8 text-center text-gray-500 text-xs">{h}</div>
            ))}
          </div>
          {/* Data rows */}
          {days.map(day => {
            const row = data.find(r => r.day === day) || {};
            return (
              <div key={day} className="flex gap-1 mb-1">
                <div className="w-10 text-gray-400 text-xs flex items-center">{day.slice(0, 3)}</div>
                {hours.map(h => {
                  const val = row[h] || 0;
                  return (
                    <div
                      key={h}
                      className="w-8 h-7 rounded-sm flex items-center justify-center text-xs"
                      style={{
                        backgroundColor: val === 0 ? '#1f2937' : `rgba(168, 85, 247, ${Math.max(0.1, val / max)})`,
                        color: val / max > 0.5 ? '#fff' : '#6b7280',
                      }}
                      title={`${day} ${h}:00 — ${val} events`}
                    >
                      {val > 0 ? val : ''}
                    </div>
                  );
                })}
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
}
