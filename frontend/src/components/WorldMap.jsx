import { useState, useEffect, useRef } from 'react';
import { ComposableMap, Geographies, Geography, Marker, ZoomableGroup } from 'react-simple-maps';
import { api } from '../services/api';

const GEO_URL = 'https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json';

function markerColor(count, maxCount) {
  const ratio = count / maxCount;
  if (ratio > 0.6) return '#ef4444';
  if (ratio > 0.3) return '#f97316';
  if (ratio > 0.1) return '#eab308';
  return '#a855f7';
}

function markerRadius(count, maxCount) {
  const logRatio = Math.log(count + 1) / Math.log(maxCount + 1);
  return 3 + logRatio * 14;
}

export default function WorldMap() {
  const [markers, setMarkers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [tooltip, setTooltip] = useState({ visible: false, content: null, x: 0, y: 0 });
  const containerRef = useRef(null);

  useEffect(() => {
    api.geoMap()
      .then(res => {
        const raw = (res && res.data) ? res.data : (Array.isArray(res) ? res : []);
        const points = raw.filter(
          m => m.lat != null && m.lon != null &&
               m.lat >= -90 && m.lat <= 90 &&
               m.lon >= -180 && m.lon <= 180
        );
        setMarkers(points);
        setLoading(false);
      })
      .catch(() => {
        setError('Failed to load geolocation data');
        setLoading(false);
      });
  }, []);

  const maxCount = markers.reduce((acc, m) => Math.max(acc, m.count), 1);

  const handleMouseMove = (e) => {
    if (!tooltip.visible) return;
    const rect = containerRef.current?.getBoundingClientRect();
    if (!rect) return;
    setTooltip(t => ({ ...t, x: e.clientX - rect.left, y: e.clientY - rect.top }));
  };

  const showTooltip = (m, e) => {
    const rect = containerRef.current?.getBoundingClientRect();
    if (!rect) return;
    setTooltip({
      visible: true,
      content: m,
      x: e.clientX - rect.left,
      y: e.clientY - rect.top,
    });
  };

  const hideTooltip = () => setTooltip(t => ({ ...t, visible: false }));

  return (
    <section className="bg-gray-900 border border-gray-800 rounded-xl p-6">
      <h2 className="text-white font-semibold mb-1">Threat Origin Map</h2>
      <p className="text-gray-400 text-sm mb-4">IP addresses mapped to geolocation</p>

      {loading ? (
        <div className="h-[480px] bg-gray-800 rounded-lg animate-pulse" />
      ) : error ? (
        <div className="h-[480px] bg-gray-800 rounded-lg flex items-center justify-center">
          <p className="text-red-400 text-sm">{error}</p>
        </div>
      ) : (
        <div
          ref={containerRef}
          className="relative rounded-lg overflow-hidden border border-gray-700 bg-gray-950"
          style={{ height: 480 }}
          onMouseMove={handleMouseMove}
        >
          <ComposableMap
            projection="geoMercator"
            projectionConfig={{ scale: 140, center: [0, 20] }}
            style={{ width: '100%', height: '100%' }}
          >
            <ZoomableGroup>
              <Geographies geography={GEO_URL}>
                {({ geographies }) =>
                  geographies.map(geo => (
                    <Geography
                      key={geo.rsmKey}
                      geography={geo}
                      fill="#1f2937"
                      stroke="#374151"
                      strokeWidth={0.5}
                      style={{
                        default: { outline: 'none' },
                        hover: { fill: '#374151', outline: 'none' },
                        pressed: { outline: 'none' },
                      }}
                    />
                  ))
                }
              </Geographies>

              {markers.map(m => {
                const color = markerColor(m.count, maxCount);
                const r = markerRadius(m.count, maxCount);
                return (
                  <Marker
                    key={`${m.lat}-${m.lon}-${m.country}`}
                    coordinates={[m.lon, m.lat]}
                  >
                    <circle
                      r={r}
                      fill={color}
                      fillOpacity={0.65}
                      stroke={color}
                      strokeWidth={1}
                      strokeOpacity={0.9}
                      style={{ cursor: 'pointer' }}
                      onMouseEnter={e => showTooltip(m, e)}
                      onMouseMove={e => showTooltip(m, e)}
                      onMouseLeave={hideTooltip}
                    />
                  </Marker>
                );
              })}
            </ZoomableGroup>
          </ComposableMap>

          {tooltip.visible && tooltip.content && (
            <div
              className="absolute z-20 pointer-events-none bg-gray-800 border border-gray-700 rounded-lg shadow-xl px-3 py-2 text-sm"
              style={{
                left: Math.min(tooltip.x + 14, 400),
                top: Math.max(tooltip.y - 72, 8),
              }}
            >
              <div className="font-semibold text-white mb-0.5">{tooltip.content.country}</div>
              <div className="text-gray-300">
                Attacks: <strong className="text-white">{tooltip.content.count.toLocaleString()}</strong>
              </div>
              <div className="text-gray-500 text-xs mt-0.5">
                {tooltip.content.lat.toFixed(2)}, {tooltip.content.lon.toFixed(2)}
              </div>
            </div>
          )}
        </div>
      )}

      <div className="flex items-center gap-6 mt-4 text-xs text-gray-400">
        <span className="flex items-center gap-1.5">
          <span className="inline-block w-2.5 h-2.5 rounded-full" style={{ background: '#a855f7' }} />
          Low
        </span>
        <span className="flex items-center gap-1.5">
          <span className="inline-block w-2.5 h-2.5 rounded-full" style={{ background: '#eab308' }} />
          Medium
        </span>
        <span className="flex items-center gap-1.5">
          <span className="inline-block w-2.5 h-2.5 rounded-full" style={{ background: '#f97316' }} />
          High
        </span>
        <span className="flex items-center gap-1.5">
          <span className="inline-block w-2.5 h-2.5 rounded-full" style={{ background: '#ef4444' }} />
          Critical
        </span>
        <span className="ml-auto">{markers.length} locations</span>
      </div>
    </section>
  );
}
