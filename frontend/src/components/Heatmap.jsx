import { useState, useEffect } from 'react';
import { api } from '../services/api';

// Multi-stop thermal gradient: near-black → indigo → purple → orange → yellow
const COLOR_STOPS = [
  [0,    [15, 23, 42]],    // slate-950 (zero attacks)
  [0.01, [30, 27, 75]],    // indigo-950 (any activity)
  [0.25, [79, 70, 229]],   // indigo-500
  [0.5,  [168, 85, 247]],  // purple-500
  [0.75, [234, 88, 12]],   // orange-600
  [1.0,  [234, 179, 8]],   // yellow-500
];

function heatColor(val, max) {
  if (!val || val === 0) return `rgb(${COLOR_STOPS[0][1].join(',')})`;
  const t = Math.min(val / max, 1);

  let i = 0;
  while (i < COLOR_STOPS.length - 2 && t >= COLOR_STOPS[i + 1][0]) i++;

  const [t0, c0] = COLOR_STOPS[i];
  const [t1, c1] = COLOR_STOPS[i + 1];
  const ratio = t1 === t0 ? 0 : (t - t0) / (t1 - t0);

  const r = Math.round(c0[0] + ratio * (c1[0] - c0[0]));
  const g = Math.round(c0[1] + ratio * (c1[1] - c0[1]));
  const b = Math.round(c0[2] + ratio * (c1[2] - c0[2]));
  return `rgb(${r},${g},${b})`;
}

export default function Heatmap() {
  const [payload, setPayload] = useState({ hours: [], days: [], data: [] });
  const [loading, setLoading] = useState(true);
  const [hovered, setHovered] = useState(null);

  useEffect(() => {
    api.heatmap()
      .then(res => { setPayload(res); setLoading(false); })
      .catch(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <section className="bg-gray-900 border border-gray-800 rounded-xl p-6">
        <div className="animate-pulse h-56 bg-gray-800 rounded" />
      </section>
    );
  }

  const { hours, days, data } = payload;
  const max = data.reduce((m, row) => Math.max(m, ...hours.map(h => row[h] || 0)), 1);

  return (
    <section className="bg-gray-900 border border-gray-800 rounded-xl p-6">
      <div className="flex items-start justify-between mb-1">
        <div>
          <h2 className="text-white font-semibold">Attack Heatmap</h2>
          <p className="text-gray-400 text-sm mt-0.5">Hour of day vs day of week</p>
        </div>
        {/* Live hover readout */}
        <div className="text-right min-h-[36px]">
          {hovered ? (
            <div className="text-sm">
              <span className="text-white font-medium">{hovered.day}</span>
              <span className="text-gray-400"> at </span>
              <span className="text-white font-medium">{hovered.hour}:00</span>
              <br />
              <span className="font-bold" style={{ color: heatColor(hovered.val, max) }}>
                {hovered.val.toLocaleString()}
              </span>
              <span className="text-gray-400 text-xs"> events</span>
            </div>
          ) : (
            <span className="text-gray-600 text-xs">hover cell for detail</span>
          )}
        </div>
      </div>

      <div className="overflow-x-auto mt-4">
        <div className="inline-block">
          {/* Hour labels */}
          <div className="flex ml-10 mb-1">
            {hours.map(h => (
              <div key={h} className="w-7 text-center text-gray-600 text-xs">{h}</div>
            ))}
          </div>

          {/* Rows */}
          {days.map(day => {
            const row = data.find(r => r.day === day) || {};
            return (
              <div key={day} className="flex mb-0.5">
                <div className="w-10 text-gray-500 text-xs flex items-center shrink-0 pr-1">
                  {day.slice(0, 3)}
                </div>
                {hours.map(h => {
                  const val = row[h] || 0;
                  const bg = heatColor(val, max);
                  const isHot = hovered?.day === day && hovered?.hour === h;
                  return (
                    <div
                      key={h}
                      className="w-7 h-7 rounded-[2px] transition-all duration-75"
                      style={{
                        backgroundColor: bg,
                        outline: isHot ? `2px solid white` : 'none',
                        outlineOffset: '-1px',
                        transform: isHot ? 'scale(1.2)' : 'scale(1)',
                        zIndex: isHot ? 10 : 1,
                        position: 'relative',
                      }}
                      onMouseEnter={() => setHovered({ day, hour: h, val })}
                      onMouseLeave={() => setHovered(null)}
                      title={`${day} ${h}:00 — ${val.toLocaleString()} events`}
                    />
                  );
                })}
              </div>
            );
          })}
        </div>
      </div>

      {/* Color scale legend */}
      <div className="flex items-center gap-3 mt-5">
        <span className="text-gray-500 text-xs">None</span>
        <div
          className="h-2.5 rounded flex-1"
          style={{
            maxWidth: 240,
            background: 'linear-gradient(to right, #1e1b4b, #4f46e5, #a855f7, #ea580c, #eab308)',
          }}
        />
        <span className="text-gray-500 text-xs">Peak</span>
      </div>
    </section>
  );
}
