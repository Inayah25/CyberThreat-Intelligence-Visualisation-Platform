const BASE_URL = '/api';

async function request(path) {
  const res = await fetch(`${BASE_URL}${path}`);
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  const json = await res.json();
  if (!json.success) throw new Error(json.error || 'Unknown error');
  return json.data;
}

export const bruteApi = {
  summary: () => request('/brute/summary'),
  topUsernames: (limit = 20) => request(`/brute/top-usernames?limit=${limit}`),
  topPasswords: (limit = 20) => request(`/brute/top-passwords?limit=${limit}`),
  topPairs: (limit = 20) => request(`/brute/top-pairs?limit=${limit}`),
  passwordTypes: () => request('/brute/password-types'),
  passwordLengths: () => request('/brute/password-lengths'),
  topIps: (limit = 20) => request(`/brute/top-ips?limit=${limit}`),
  timeline: () => request('/brute/timeline'),
};
