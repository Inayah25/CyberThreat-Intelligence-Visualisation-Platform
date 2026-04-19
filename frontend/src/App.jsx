import { useState, useEffect } from 'react';
import Overview from './components/Overview';
import TrendChart from './components/TrendChart';
import AttackTypes from './components/AttackTypes';
import Protocols from './components/Protocols';
import TopPorts from './components/TopPorts';
import Countries from './components/Countries';
import Heatmap from './components/Heatmap';
import EventTable from './components/EventTable';
import CredentialIntelligence from './components/CredentialIntelligence';
import { api } from './services/api';

function App() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [health, setHealth] = useState(null);
  const [activeTab, setActiveTab] = useState('dashboard');

  useEffect(() => {
    api.health()
      .then(data => {
        setHealth(data);
        setLoading(false);
      })
      .catch(err => {
        setError('Cannot connect to backend. Make sure Flask is running on port 5000.');
        setLoading(false);
      });
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-gray-950 text-white">
        <div className="text-center">
          <div className="animate-spin h-10 w-10 border-4 border-purple-500 border-t-transparent rounded-full mx-auto mb-4" />
          <p className="text-gray-400">Loading Cyber Threat Dashboard...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-gray-950 text-white">
        <div className="text-center max-w-md p-8">
          <div className="text-6xl mb-4">⚠</div>
          <h2 className="text-xl font-semibold text-red-400 mb-2">Backend Offline</h2>
          <p className="text-gray-400">{error}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-950 text-white">
      <header className="border-b border-gray-800 bg-gray-900/80 backdrop-blur sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-6 py-4">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <div className="h-8 w-8 rounded bg-purple-600 flex items-center justify-center text-sm font-bold">CT</div>
              <h1 className="text-xl font-bold text-white">Cyber Threat Dashboard</h1>
            </div>
            <div className="flex items-center gap-4 text-sm text-gray-400">
              <span className="flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-full bg-green-500 animate-pulse" />
                Live
              </span>
              {health && (
                <span className="text-gray-500">
                  {health.data_loaded ? `${health.data_loaded.toLocaleString()} events loaded` : 'Loading...'}
                </span>
              )}
            </div>
          </div>
          <nav className="flex gap-2">
            <button
              onClick={() => setActiveTab('dashboard')}
              className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                activeTab === 'dashboard'
                  ? 'bg-purple-600 text-white'
                  : 'text-gray-400 hover:text-white hover:bg-gray-800'
              }`}
            >
              Dashboard
            </button>
            <button
              onClick={() => setActiveTab('credential-intelligence')}
              className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                activeTab === 'credential-intelligence'
                  ? 'bg-purple-600 text-white'
                  : 'text-gray-400 hover:text-white hover:bg-gray-800'
              }`}
            >
              Credential Intelligence
            </button>
          </nav>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-6 py-8">
        {activeTab === 'dashboard' && (
          <div className="space-y-8">
            <Overview />
            <TrendChart />
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <AttackTypes />
              <Protocols />
            </div>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <TopPorts />
              <Countries />
            </div>
            <Heatmap />
            <EventTable />
          </div>
        )}
        {activeTab === 'credential-intelligence' && <CredentialIntelligence />}
      </main>

      <footer className="border-t border-gray-800 mt-12 py-6 text-center text-gray-500 text-sm">
        Cyber Threat Dashboard — Honeypot Event Monitor
      </footer>
    </div>
  );
}

export default App;
