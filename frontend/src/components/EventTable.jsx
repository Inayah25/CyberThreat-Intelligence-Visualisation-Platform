import { useState, useEffect, useCallback } from 'react';
import { api } from '../services/api';

const PAGE_SIZE = 50;

const columns = [
  { key: 'timestamp', label: 'Time' },
  { key: 'srcIp', label: 'Source IP' },
  { key: 'srcPort', label: 'Src Port' },
  { key: 'srcCountryName', label: 'Country' },
  { key: 'srcOrg', label: 'Organization' },
  { key: 'dstIp', label: 'Dest IP' },
  { key: 'dstPort', label: 'Port' },
  { key: 'protocol', label: 'Protocol' },
  { key: 'attackType', label: 'Attack Type' },
];

export default function EventTable() {
  const [events, setEvents] = useState([]);
  const [pagination, setPagination] = useState({ page: 1, total: 0, pages: 0 });
  const [loading, setLoading] = useState(false);
  const [filters, setFilters] = useState({});
  const [protocolOptions, setProtocolOptions] = useState([]);
  const [attackTypeOptions, setAttackTypeOptions] = useState([]);

  useEffect(() => {
    Promise.all([api.protocols(), api.types(50)])
      .then(([p, a]) => {
        setProtocolOptions(p.data?.map(x => x.protocol) || []);
        setAttackTypeOptions(a.data?.map(x => x.type) || []);
      })
      .catch(console.error);
  }, []);

  const fetchEvents = useCallback((page = 1, f = filters) => {
    setLoading(true);
    const params = { page, limit: PAGE_SIZE, ...f };
    api.details(params)
      .then(res => {
        setEvents(res.events || []);
        setPagination(res.pagination || { page: 1, total: 0, pages: 0 });
        setLoading(false);
      })
      .catch(err => {
        console.error(err);
        setLoading(false);
      });
  }, [filters]);

  useEffect(() => {
    fetchEvents(1, filters);
  }, []);

  const handleFilterChange = (key, value) => {
    const newFilters = { ...filters, [key]: value || undefined };
    setFilters(newFilters);
    fetchEvents(1, newFilters);
  };

  const handlePage = (newPage) => {
    if (newPage < 1 || newPage > pagination.pages) return;
    fetchEvents(newPage, filters);
  };

  return (
    <section className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
      <div className="p-6 border-b border-gray-800">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h2 className="text-white font-semibold">Event Details</h2>
            <p className="text-gray-400 text-sm">
              {pagination.total?.toLocaleString()} total events
            </p>
          </div>
          <div className="flex gap-2 flex-wrap">
            <select
              className="bg-gray-800 border border-gray-700 text-gray-300 text-xs rounded px-2 py-1.5"
              onChange={e => handleFilterChange('protocol', e.target.value)}
            >
              <option value="">All Protocols</option>
              {protocolOptions.map(p => (
                <option key={p} value={p}>{p}</option>
              ))}
            </select>
            <select
              className="bg-gray-800 border border-gray-700 text-gray-300 text-xs rounded px-2 py-1.5"
              onChange={e => handleFilterChange('attackType', e.target.value)}
            >
              <option value="">All Attack Types</option>
              {attackTypeOptions.map(t => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>
            {Object.values(filters).some(Boolean) && (
              <button
                className="text-xs text-purple-400 hover:text-purple-300 px-2 py-1.5"
                onClick={() => { setFilters({}); fetchEvents(1, {}); }}
              >
                Clear Filters
              </button>
            )}
          </div>
        </div>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-xs">
          <thead>
            <tr className="bg-gray-800/50 text-gray-400">
              {columns.map(col => (
                <th key={col.key} className="px-3 py-2.5 text-left font-medium whitespace-nowrap">
                  {col.label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {loading ? (
              [...Array(10)].map((_, i) => (
                <tr key={i} className="border-t border-gray-800">
                  {columns.map(col => (
                    <td key={col.key} className="px-3 py-2">
                      <div className="h-3 bg-gray-800 rounded animate-pulse" />
                    </td>
                  ))}
                </tr>
              ))
            ) : events.length === 0 ? (
              <tr>
                <td colSpan={columns.length} className="px-3 py-12 text-center text-gray-500">
                  No events found
                </td>
              </tr>
            ) : (
              events.map((event, i) => (
                <tr
                  key={i}
                  className="border-t border-gray-800 hover:bg-gray-800/40 transition-colors"
                >
                  {columns.map(col => (
                    <td key={col.key} className="px-3 py-2 text-gray-300 whitespace-nowrap">
                      {col.key === 'timestamp'
                        ? new Date(event[col.key]).toLocaleString()
                        : event[col.key] ?? '—'}
                    </td>
                  ))}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <div className="p-4 border-t border-gray-800 flex items-center justify-between">
        <span className="text-gray-500 text-xs">
          Page {pagination.page} of {pagination.pages || 1}
        </span>
        <div className="flex gap-1">
          <button
            className="px-3 py-1 bg-gray-800 text-gray-300 text-xs rounded disabled:opacity-40 hover:bg-gray-700 transition-colors"
            disabled={pagination.page <= 1}
            onClick={() => handlePage(pagination.page - 1)}
          >
            Prev
          </button>
          {[...Array(Math.min(5, pagination.pages || 1))].map((_, i) => {
            const page = Math.max(1, Math.min(pagination.page - 2 + i, pagination.pages || 1));
            return (
              <button
                key={page}
                className={`px-3 py-1 text-xs rounded transition-colors ${
                  page === pagination.page
                    ? 'bg-purple-600 text-white'
                    : 'bg-gray-800 text-gray-300 hover:bg-gray-700'
                }`}
                onClick={() => handlePage(page)}
              >
                {page}
              </button>
            );
          })}
          <button
            className="px-3 py-1 bg-gray-800 text-gray-300 text-xs rounded disabled:opacity-40 hover:bg-gray-700 transition-colors"
            disabled={pagination.page >= pagination.pages}
            onClick={() => handlePage(pagination.page + 1)}
          >
            Next
          </button>
        </div>
      </div>
    </section>
  );
}
