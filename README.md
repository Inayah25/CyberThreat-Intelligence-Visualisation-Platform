# Cyber Attack Intelligence Visualization Platform

## Overview

A full-stack cybersecurity threat intelligence dashboard that transforms real-world honeypot and brute force attack data into interactive visual intelligence. The platform ingests data from two public datasets, processes and serves it through a Flask REST API, and visualises it through a dark-themed React dashboard with multiple interactive features.

## Live Demo

🔗 https://cyber-threat-platform-e20y.onrender.com

> Note: The app is hosted on Render's free tier. If it has been inactive it may take 30–60 seconds to wake up on first load.

## Datasets

| Dataset | Source | Records |
|---|---|---|
| Multi-Regional Azure Cloud Honeynet (2025) | Zenodo — Universidad Rey Juan Carlos | 264,850 attack events |
| SSH Brute Force Credential Dataset | Kaggle | 38,887 credential attempts |

## Features

- **Overview Dashboard** — Summary statistics, threat origin world map with clustering, honeypot distribution, protocol breakdown, top attacker countries, attack timeline, and intensity heatmap
- **Credential Intelligence** — Analysis of SSH brute force attempts including top usernames, passwords, credential pairs, password type distribution, and attacking IPs
- **Threat Intelligence** — MITRE ATT&CK framework mapping connecting observed attack patterns to named threat techniques and recommended mitigations
- **Country Comparison** — Side by side comparison of attack patterns between any two countries including attack types, protocols, ports, and time-of-day activity
- **IP Reputation Lookup** — Real-time IP investigation combining AbuseIPDB global threat intelligence with local honeypot observations
- **Report Generator** — Filterable intelligence reports with PDF download

## Tech Stack

**Backend**
- Python 3
- Flask — REST API web framework
- Pandas — data processing and aggregation
- Gunicorn — production WSGI server
- WeasyPrint — PDF report generation
- python-dotenv — environment variable management

**Frontend**
- React 18 (Vite)
- React Router — client-side routing
- Recharts — charting library
- React-Leaflet — interactive world map
- Axios — HTTP client for API calls

**External APIs**
- [MITRE ATT&CK STIX API](https://attack-taxii.mitre.org) — live threat intelligence data fetched from the official mitre-attack/attack-stix-data GitHub repository at server startup
- [AbuseIPDB API](https://www.abuseipdb.com) — real-time IP reputation and abuse confidence scoring

## Project Structure
```
CyberThreat-Intelligence-Visualisation-Platform/
├── backend/
│   ├── app.py                    # Flask server and all API routes
│   ├── clean_data.py             # Honeynet dataset cleaning script
│   ├── clean_brute_force.py      # Brute force dataset cleaning script
│   ├── test_app.py               # Pytest automated tests
│   └── requirements.txt
├── data/
│   ├── HoneyAllEvents_Clean.csv  # Cleaned honeynet dataset
│   ├── HoneyNetEvents_Clean.csv  # Cleaned honeynet dataset (subset)
│   ├── BruteForce_Clean.csv      # Cleaned brute force dataset
│   └── enterprise-attack.json   # MITRE ATT&CK local cache
├── frontend/
│   ├── src/
│   │   ├── components/           # All React page components
│   │   ├── services/             # Axios API call functions
│   │   └── App.jsx               # Routing and navigation
│   ├── dist/                     # Production build (served by Flask)
│   └── package.json
├── render.yaml                   # Render deployment configuration
└── README.md
```
## Running Locally

### Prerequisites
- Python 3.10 or higher
- Node.js 18 or higher
- npm

### 1. Clone the repository

```bash
git clone https://github.com/Inayah25/CyberThreat-Intelligence-Visualisation-Platform.git
cd CyberThreat-Intelligence-Visualisation-Platform
```

### 2. Set up the backend

```bash
cd backend
pip install -r requirements.txt
```

Create a `.env` file inside the `backend/` folder:
ABUSEIPDB_API_KEY=your_api_key_here
Get a free API key at [abuseipdb.com](https://www.abuseipdb.com)

### 3. Start the Flask backend

```bash
python app.py
```

Flask will start on `http://localhost:5000`

### 4. Set up the frontend (in a second terminal)

```bash
cd frontend
npm install
npm run dev
```

React will start on `http://localhost:5173`

### 5. Open the dashboard

Go to `http://localhost:5173` in your browser.

> Both terminals must be running simultaneously for the app to work.

## Running Tests

```bash
cd backend
pytest test_app.py -v
```

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| ABUSEIPDB_API_KEY | Yes | Free API key from abuseipdb.com — used for IP reputation lookup |

## Deployment

The app is deployed on [Render](https://render.com) using the included `render.yaml` configuration. Flask serves both the API routes and the compiled React frontend from the `frontend/dist/` folder.

## Acknowledgements

- Feito-Casares, E., Gómez-Talal, I., Rojo-Álvarez, J.L. — Azure Cloud Honeynet Dataset (2025), Universidad Rey Juan Carlos
- MITRE ATT&CK® — [attack.mitre.org](https://attack.mitre.org)
- AbuseIPDB — [abuseipdb.com](https://www.abuseipdb.com)
