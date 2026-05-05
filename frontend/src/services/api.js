const BASE_URL = '/api';

async function request(path) {
  const res = await fetch(`${BASE_URL}${path}`);
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  const json = await res.json();
  if (!json.success) throw new Error(json.error || 'Unknown error');
  return json.data;
}

export const api = {
  overview: () => request('/overview'),
  trends: (groupBy = 'day') => request(`/trends?groupBy=${groupBy}`),
  types: (limit = 20) => request(`/types?limit=${limit}`),
  protocols: () => request('/protocols'),
  ports: (limit = 15) => request(`/ports?limit=${limit}`),
  countries: (limit = 20) => request(`/countries?limit=${limit}`),
  heatmap: () => request('/heatmap'),
  details: (params = {}) => {
    const sp = new URLSearchParams(params);
    return request(`/details?${sp}`);
  },
  topSources: (limit = 20) => request(`/top-sources?limit=${limit}`),
  geoMap: () => request('/geo-map'),
  threatMapping: () => request('/threat-mapping'),
  health: () => fetch(`${BASE_URL}/health`).then(r => r.json()),
};
