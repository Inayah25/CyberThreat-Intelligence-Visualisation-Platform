"""
Backend API tests for Cyber Threat Dashboard.

Route mapping (user-facing names → actual endpoints):
  summary       → /api/overview
  top-countries → /api/countries
  timeline      → /api/trends
"""

import pytest
from app import app as flask_app


@pytest.fixture(scope="session")
def client():
    """Create a Flask test client. Data loads once for the whole test session."""
    flask_app.config["TESTING"] = True
    with flask_app.test_client() as c:
        # Trigger data load before tests run
        c.get("/api/health")
        yield c


# ─── Overview (summary) ──────────────────────────────────────────────────────

def test_summary_returns_200(client):
    resp = client.get("/api/overview")
    assert resp.status_code == 200


def test_summary_has_required_fields(client):
    resp = client.get("/api/overview")
    data = resp.get_json()["data"]
    assert "totalEvents" in data
    assert "uniqueSourceIPs" in data
    assert "countries" in data


# ─── Countries (top-countries) ────────────────────────────────────────────────

def test_top_countries_returns_200(client):
    resp = client.get("/api/countries")
    assert resp.status_code == 200


def test_top_countries_is_list(client):
    resp = client.get("/api/countries")
    data = resp.get_json()["data"]
    assert isinstance(data["data"], list)
    assert len(data["data"]) >= 1


# ─── Brute force summary ─────────────────────────────────────────────────────

def test_brute_summary_returns_200(client):
    resp = client.get("/api/brute/summary")
    assert resp.status_code == 200


def test_brute_summary_has_required_fields(client):
    resp = client.get("/api/brute/summary")
    data = resp.get_json()["data"]
    assert "totalAttempts" in data
    assert "uniqueUsernames" in data
    assert "uniquePasswords" in data


# ─── Brute force top usernames ────────────────────────────────────────────────

def test_brute_top_usernames_returns_200(client):
    resp = client.get("/api/brute/top-usernames")
    assert resp.status_code == 200


# ─── Compare countries ────────────────────────────────────────────────────────

def test_compare_countries_missing_params_returns_400(client):
    resp = client.get("/api/compare-countries")
    assert resp.status_code == 400


def test_compare_countries_valid_returns_200(client):
    resp = client.get("/api/compare-countries?country1=China&country2=Russia")
    assert resp.status_code == 200


# ─── IP lookup ────────────────────────────────────────────────────────────────

def test_ip_lookup_missing_param_returns_400(client):
    resp = client.get("/api/ip-lookup")
    assert resp.status_code == 400


# ─── Trends (timeline) ───────────────────────────────────────────────────────

def test_timeline_returns_200(client):
    resp = client.get("/api/trends")
    assert resp.status_code == 200


def test_timeline_is_list(client):
    resp = client.get("/api/trends")
    data = resp.get_json()["data"]
    assert isinstance(data["data"], list)
