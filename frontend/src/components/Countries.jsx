import { useState, useEffect } from 'react';
import { api } from '../services/api';

export default function Countries() {
  const [data, setData] = useState([]);

  useEffect(() => {
    api.countries(10).then(res => setData(res.data || [])).catch(console.error);
  }, []);

  const max = Math.max(...data.map(d => d.count), 1);

  return (
    <section className="bg-gray-900 border border-gray-800 rounded-xl p-6">
      <h2 className="text-white font-semibold mb-1">Source Countries</h2>
      <p className="text-gray-400 text-sm mb-6">Top attacking nations</p>
      <div className="space-y-3">
        {data.map((item, i) => (
          <div key={item.country} className="flex items-center gap-3">
            <span className="text-gray-400 text-xs w-4 text-right">{i + 1}</span>
            <span className="text-white text-sm w-28 truncate">{item.country}</span>
            <div className="flex-1 bg-gray-800 rounded-full h-1.5 overflow-hidden">
              <div
                className="h-full rounded-full"
                style={{
                  width: `${(item.count / max) * 100}%`,
                  background: `hsl(${260 - i * 18}, 80%, 65%)`,
                }}
              />
            </div>
            <span className="text-gray-400 text-xs w-16 text-right">{item.count.toLocaleString()}</span>
          </div>
        ))}
      </div>
    </section>
  );
}
