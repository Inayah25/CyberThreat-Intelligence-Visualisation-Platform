"""
Cyber Threat Dashboard - Flask Backend
Provides REST API endpoints for dashboard visualizations
"""

from __future__ import annotations

import os
from datetime import datetime
from functools import wraps
import logging

from flask import Flask, jsonify, request
from flask_cors import CORS
import pandas as pd

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "http://localhost:5173"}})

_df: pd.DataFrame | None = None
_data_loaded: bool = False
_brute_df: pd.DataFrame | None = None


def handle_errors(f):
    """Decorator for graceful error handling."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            logger.error(f"Error in {f.__name__}: {e}", exc_info=True)
            return jsonify({"error": str(e), "success": False}), 500
    return decorated_function


def load_data() -> None:
    """Load and combine CSV data files."""
    global _df, _data_loaded, _brute_df

    if _data_loaded:
        return

    data_dir = os.path.join(os.path.dirname(__file__), "..", "data")
    honey_all_path = os.path.join(data_dir, "HoneyAllEvents_Clean.csv")
    honey_net_path = os.path.join(data_dir, "HoneyNetEvents_Clean.csv")
    brute_force_path = os.path.join(data_dir, "BruteForce_Clean.csv")

    logger.info("Loading CSV files...")

    df_all = pd.read_csv(honey_all_path)
    df_net = pd.read_csv(honey_net_path)

    _df = pd.concat([df_all, df_net], ignore_index=True)

    # Load brute force data
    try:
        _brute_df = pd.read_csv(brute_force_path)
        _brute_df["timestamp"] = pd.to_datetime(_brute_df["timestamp"])
        _brute_df["date_only"] = _brute_df["timestamp"].dt.strftime("%Y-%m-%d")
        logger.info(f"Loaded {_brute_df.shape[0]} brute force attempts")
    except FileNotFoundError:
        _brute_df = None
        logger.warning("Brute force data not found")

    _df["timestamp"] = pd.to_datetime(_df["timestamp"], format="ISO8601", utc=True)
    _df = _df.sort_values("timestamp").reset_index(drop=True)

    _df["date_only"] = _df["timestamp"].dt.date
    _df["hour_of_day"] = _df["timestamp"].dt.hour
    _df["day_of_week"] = _df["timestamp"].dt.day_name()

    _data_loaded = True
    logger.info(f"Loaded {_df.shape[0]} events")


def ensure_data() -> None:
    """Ensure data is loaded before each request."""
    global _df
    if _df is None:
        load_data()


def safe_response(data: dict, **kwargs) -> tuple:
    """Create a JSON response with success flag."""
    response = {"success": True, "data": data}
    response.update(kwargs)
    return jsonify(response), 200


@app.route("/api/overview", methods=["GET"])
@handle_errors
def get_overview():
    """Returns total events, unique IPs, date range, etc."""
    ensure_data()

    total_events = len(_df)
    unique_src_ips = int(_df["srcIp"].nunique())
    unique_dst_ips = int(_df["dstIp"].nunique())
    date_min = _df["timestamp"].min()
    date_max = _df["timestamp"].max()

    top_country_dict: dict[str, int] = {}
    if not _df["srcCountryName"].empty:
        top_country_entry = _df["srcCountryName"].value_counts().head(1)
        if not top_country_entry.empty:
            top_country_dict = {top_country_entry.index[0]: int(top_country_entry.iloc[0])}

    overview = {
        "totalEvents": total_events,
        "uniqueSourceIPs": unique_src_ips,
        "uniqueDestinationIPs": unique_dst_ips,
        "dateRange": {
            "start": date_min.isoformat() if pd.notna(date_min) else None,
            "end": date_max.isoformat() if pd.notna(date_max) else None,
        },
        "protocols": int(_df["protocol"].nunique()),
        "attackTypes": int(_df["attackType"].nunique()),
        "countries": int(_df["srcCountryName"].nunique()),
        "topSourceCountry": top_country_dict,
    }

    return safe_response(overview)


@app.route("/api/trends", methods=["GET"])
@handle_errors
def get_trends():
    """Time-series data (events over time, grouped by day or hour)."""
    ensure_data()

    group_by = request.args.get("groupBy", "day")

    if group_by == "hour":
        _df["time_group"] = _df["timestamp"].dt.strftime("%Y-%m-%d %H:00")
    else:
        _df["time_group"] = _df["timestamp"].dt.strftime("%Y-%m-%d")

    trends = _df.groupby("time_group").size().reset_index(name="count")
    trends = trends.sort_values("time_group")

    return safe_response({
        "groupBy": group_by,
        "data": [
            {"time_group": str(r["time_group"]), "count": int(r["count"])}
            for r in trends.to_dict(orient="records")
        ],
    })


@app.route("/api/types", methods=["GET"])
@handle_errors
def get_types():
    """Attack type distribution."""
    ensure_data()

    limit = int(request.args.get("limit", 20))
    type_counts = _df["attackType"].value_counts().head(limit).reset_index()
    type_counts.columns = ["type", "count"]
    type_counts["count"] = type_counts["count"].astype(int)

    return safe_response({
        "data": type_counts.to_dict(orient="records"),
        "total": int(_df["attackType"].nunique()),
    })


@app.route("/api/protocols", methods=["GET"])
@handle_errors
def get_protocols():
    """Protocol distribution."""
    ensure_data()

    protocol_counts = _df["protocol"].value_counts().reset_index()
    protocol_counts.columns = ["protocol", "count"]
    protocol_counts["count"] = protocol_counts["count"].astype(int)

    return safe_response({
        "data": protocol_counts.to_dict(orient="records"),
    })


@app.route("/api/ports", methods=["GET"])
@handle_errors
def get_ports():
    """Top ports targeted."""
    ensure_data()

    limit = int(request.args.get("limit", 15))
    port_counts = _df["dstPort"].value_counts().head(limit).reset_index()
    port_counts.columns = ["port", "count"]
    port_counts["port"] = port_counts["port"].astype(int)
    port_counts["count"] = port_counts["count"].astype(int)

    return safe_response({
        "data": port_counts.to_dict(orient="records"),
    })


@app.route("/api/countries", methods=["GET"])
@handle_errors
def get_countries():
    """Geographic distribution."""
    ensure_data()

    limit = int(request.args.get("limit", 20))
    country_counts = _df["srcCountryName"].value_counts().head(limit).reset_index()
    country_counts.columns = ["country", "count"]
    country_counts["count"] = country_counts["count"].astype(int)

    return safe_response({
        "data": country_counts.to_dict(orient="records"),
        "total": int(_df["srcCountryName"].nunique()),
    })


@app.route("/api/heatmap", methods=["GET"])
@handle_errors
def get_heatmap():
    """Data for heatmap (hour of day vs day of week)."""
    ensure_data()

    day_order = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
    heatmap_data = _df.groupby(["day_of_week", "hour_of_day"]).size().reset_index(name="count")
    heatmap_pivot = heatmap_data.pivot(index="day_of_week", columns="hour_of_day", values="count").fillna(0)
    heatmap_pivot = heatmap_pivot.reindex(day_order)

    data = []
    for day in day_order:
        row: dict[str, object] = {"day": day}
        if day in heatmap_pivot.index:
            for hour in range(24):
                val = int(heatmap_pivot.loc[day, hour]) if (hour in heatmap_pivot.columns and pd.notna(heatmap_pivot.loc[day, hour])) else 0
                row[str(hour)] = val
        else:
            for hour in range(24):
                row[str(hour)] = 0
        data.append(row)

    return safe_response({
        "hours": list(range(24)),
        "days": day_order,
        "data": data,
    })


@app.route("/api/details", methods=["GET"])
@handle_errors
def get_details():
    """Paginated recent events with filtering."""
    ensure_data()

    page = int(request.args.get("page", 1))
    limit = min(int(request.args.get("limit", 50)), 500)
    offset = (page - 1) * limit

    df_filtered = _df
    if request.args.get("protocol"):
        df_filtered = df_filtered[df_filtered["protocol"] == request.args.get("protocol")]
    if request.args.get("attackType"):
        df_filtered = df_filtered[df_filtered["attackType"] == request.args.get("attackType")]
    if request.args.get("country"):
        df_filtered = df_filtered[df_filtered["srcCountryName"] == request.args.get("country")]
    if request.args.get("port"):
        df_filtered = df_filtered[df_filtered["dstPort"] == int(request.args.get("port"))]

    total = len(df_filtered)
    df_page = df_filtered.iloc[offset:offset + limit]

    records = []
    for _, row in df_page.iterrows():
        records.append({
            "timestamp": str(row["timestamp"]),
            "srcIp": str(row["srcIp"]),
            "srcPort": int(row["srcPort"]),
            "srcCountryName": str(row["srcCountryName"]),
            "srcOrg": str(row["srcOrg"]) if pd.notna(row["srcOrg"]) else None,
            "dstIp": str(row["dstIp"]),
            "dstPort": int(row["dstPort"]),
            "dstHostname": str(row["dstHostname"]) if pd.notna(row["dstHostname"]) else None,
            "protocol": str(row["protocol"]),
            "attackType": str(row["attackType"]),
        })

    return safe_response({
        "events": records,
        "pagination": {
            "page": page,
            "limit": limit,
            "total": total,
            "pages": (total + limit - 1) // limit,
        },
    })


@app.route("/api/top-sources", methods=["GET"])
@handle_errors
def get_top_sources():
    """Top attacking source IPs."""
    ensure_data()

    limit = int(request.args.get("limit", 20))
    src_counts = _df["srcIp"].value_counts().head(limit).reset_index()
    src_counts.columns = ["ip", "count"]
    src_counts["count"] = src_counts["count"].astype(int)

    records = []
    for _, row in src_counts.iterrows():
        records.append({
            "ip": str(row["ip"]),
            "count": int(row["count"]),
            "country": str(_df[_df["srcIp"] == row["ip"]]["srcCountryName"].iloc[0]) if not _df[_df["srcIp"] == row["ip"]]["srcCountryName"].empty else None,
            "org": str(_df[_df["srcIp"] == row["ip"]]["srcOrg"].iloc[0]) if not _df[_df["srcIp"] == row["ip"]]["srcOrg"].empty and pd.notna(_df[_df["srcIp"] == row["ip"]]["srcOrg"].iloc[0]) else None,
        })

    return safe_response({"data": records})


@app.route("/api/geo-map", methods=["GET"])
@handle_errors
def get_geo_map():
    """Geographic coordinates for map visualization."""
    ensure_data()

    geo = _df[["srcLat", "srcLon", "srcCountryName", "srcIp"]].copy()
    geo = geo.dropna(subset=["srcLat", "srcLon"])
    geo["count"] = geo.groupby(["srcLat", "srcLon"])["srcIp"].transform("count")
    geo = geo.drop_duplicates(subset=["srcLat", "srcLon"])
    geo = geo.sort_values("count", ascending=False).head(200)

    return safe_response({
        "data": [
            {
                "lat": float(row["srcLat"]),
                "lon": float(row["srcLon"]),
                "country": str(row["srcCountryName"]),
                "count": int(row["count"]),
            }
            for _, row in geo.iterrows()
        ],
    })


# =============================================================================
# BRUTE FORCE API ROUTES
# =============================================================================

def ensure_brute_data() -> None:
    """Ensure brute force data is available."""
    global _brute_df
    if _brute_df is None:
        load_data()


def safe_brute_response(data: dict) -> tuple:
    """Create a JSON response for brute force endpoints."""
    return jsonify({"success": True, "data": data}), 200


@app.route("/api/brute/summary", methods=["GET"])
@handle_errors
def get_brute_summary():
    """Summary statistics for brute force attempts."""
    ensure_brute_data()
    if _brute_df is None or _brute_df.empty:
        return safe_brute_response({
            "totalAttempts": 0,
            "uniqueUsernames": 0,
            "uniquePasswords": 0,
            "uniqueIPs": 0,
            "defaultCredentialPct": 0.0,
        })

    total = len(_brute_df)
    default_creds = int(_brute_df["is_default_credential"].sum())

    return safe_brute_response({
        "totalAttempts": total,
        "uniqueUsernames": int(_brute_df["username"].nunique()),
        "uniquePasswords": int(_brute_df["password"].nunique()),
        "uniqueIPs": int(_brute_df["src_ip"].nunique()),
        "defaultCredentialPct": round((default_creds / total) * 100, 2) if total > 0 else 0.0,
    })


@app.route("/api/brute/top-usernames", methods=["GET"])
@handle_errors
def get_brute_top_usernames():
    """Top 20 usernames by attempt count."""
    ensure_brute_data()
    if _brute_df is None or _brute_df.empty:
        return safe_brute_response([])

    limit = 20
    top = _brute_df["username"].value_counts().head(limit).reset_index()
    top.columns = ["username", "count"]
    top["count"] = top["count"].astype(int)

    return safe_brute_response(top.to_dict(orient="records"))


@app.route("/api/brute/top-passwords", methods=["GET"])
@handle_errors
def get_brute_top_passwords():
    """Top 20 passwords by attempt count."""
    ensure_brute_data()
    if _brute_df is None or _brute_df.empty:
        return safe_brute_response([])

    limit = 20
    top = _brute_df["password"].value_counts().head(limit).reset_index()
    top.columns = ["password", "count"]
    top["count"] = top["count"].astype(int)

    return safe_brute_response(top.to_dict(orient="records"))


@app.route("/api/brute/top-pairs", methods=["GET"])
@handle_errors
def get_brute_top_pairs():
    """Top 20 username+password combinations by count."""
    ensure_brute_data()
    if _brute_df is None or _brute_df.empty:
        return safe_brute_response([])

    limit = 20
    top = _brute_df.groupby(["username", "password"]).size().reset_index(name="count")
    top = top.sort_values("count", ascending=False).head(limit)
    top["count"] = top["count"].astype(int)

    return safe_brute_response(top.to_dict(orient="records"))


@app.route("/api/brute/password-types", methods=["GET"])
@handle_errors
def get_brute_password_types():
    """Count of each password_type value."""
    ensure_brute_data()
    if _brute_df is None or _brute_df.empty:
        return safe_brute_response([])

    type_counts = _brute_df["password_type"].value_counts().reset_index()
    type_counts.columns = ["type", "count"]
    type_counts["count"] = type_counts["count"].astype(int)

    return safe_brute_response(type_counts.to_dict(orient="records"))


@app.route("/api/brute/password-lengths", methods=["GET"])
@handle_errors
def get_brute_password_lengths():
    """Count of attempts per password_length value."""
    ensure_brute_data()
    if _brute_df is None or _brute_df.empty:
        return safe_brute_response([])

    length_counts = _brute_df["password_length"].value_counts().sort_index().reset_index()
    length_counts.columns = ["length", "count"]
    length_counts["length"] = length_counts["length"].astype(int)
    length_counts["count"] = length_counts["count"].astype(int)

    return safe_brute_response(length_counts.to_dict(orient="records"))


@app.route("/api/brute/top-ips", methods=["GET"])
@handle_errors
def get_brute_top_ips():
    """Top 20 attacking IPs by attempt count."""
    ensure_brute_data()
    if _brute_df is None or _brute_df.empty:
        return safe_brute_response([])

    limit = 20
    top = _brute_df["src_ip"].value_counts().head(limit).reset_index()
    top.columns = ["ip", "count"]
    top["count"] = top["count"].astype(int)

    return safe_brute_response(top.to_dict(orient="records"))


@app.route("/api/brute/timeline", methods=["GET"])
@handle_errors
def get_brute_timeline():
    """Attempt counts grouped by date."""
    ensure_brute_data()
    if _brute_df is None or _brute_df.empty:
        return safe_brute_response([])

    timeline = _brute_df.groupby("date_only").size().reset_index(name="count")
    timeline.columns = ["date", "count"]
    timeline["count"] = timeline["count"].astype(int)
    timeline = timeline.sort_values("date")

    return safe_brute_response(timeline.to_dict(orient="records"))


@app.route("/api/health", methods=["GET"])
def health_check():
    """Health check endpoint."""
    global _data_loaded
    return jsonify({
        "status": "healthy",
        "data_loaded": _data_loaded,
    })


if __name__ == "__main__":
    load_data()
    app.run(host="0.0.0.0", port=5000, debug=True)
