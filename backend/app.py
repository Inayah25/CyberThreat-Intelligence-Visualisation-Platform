"""
Cyber Threat Dashboard - Flask Backend
Provides REST API endpoints for dashboard visualizations.
All aggregations are computed once at startup and served from an in-memory cache.
"""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime
from functools import wraps
import logging

import requests as http_requests
from flask import Flask, jsonify, make_response, request
from flask_cors import CORS
import pandas as pd

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "http://localhost:5173"}})

# ─── Raw data ─────────────────────────────────────────────────────────────────
_df: pd.DataFrame | None = None
_data_loaded: bool = False
_brute_df: pd.DataFrame | None = None

# ─── Pre-computed response cache ──────────────────────────────────────────────
# Built once after CSVs load. Routes just read from here.
_cache: dict = {}
_cache_built: bool = False

# ─── MITRE ATT&CK globals ─────────────────────────────────────────────────────
_attack_data: dict | None = None
_attack_loaded: bool = False
_attack_lock = threading.Lock()

ATTACK_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)

TACTIC_PHASE_TO_NAME: dict[str, str] = {
    "reconnaissance": "Reconnaissance",
    "resource-development": "Resource Development",
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "collection": "Collection",
    "command-and-control": "Command & Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}

SOURCE_TECHNIQUE_IDS: dict[str, list[str]] = {
    "Cowrie":     ["T1110", "T1110.001", "T1110.003", "T1021.004", "T1078"],
    "Dionaea":    ["T1190", "T1203", "T1059", "T1105"],
    "Sentrypeer": ["T1110", "T1078", "T1499", "T1566"],
}

BRUTE_TECHNIQUE_IDS: list[dict] = [
    {"id": "T1110.001", "count_source": "total",   "severity": "CRITICAL"},
    {"id": "T1110.003", "count_source": "total",   "severity": "HIGH"},
    {"id": "T1078.001", "count_source": "default", "severity": "CRITICAL"},
    {"id": "T1586.002", "count_source": "total",   "severity": "MEDIUM"},
]

ALL_TACTICS = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command & Control",
    "Exfiltration", "Impact",
]


# =============================================================================
# ERROR HANDLING
# =============================================================================

def handle_errors(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            logger.error(f"Error in {f.__name__}: {e}", exc_info=True)
            return jsonify({"error": str(e), "success": False}), 500
    return decorated_function


# =============================================================================
# DATA LOADING
# =============================================================================

def load_data() -> None:
    """Load CSV files into memory, then build the response cache."""
    global _df, _data_loaded, _brute_df

    if _data_loaded:
        return

    data_dir = os.path.join(os.path.dirname(__file__), "..", "data")
    honey_all_path = os.path.join(data_dir, "HoneyAllEvents_Clean.csv")
    honey_net_path = os.path.join(data_dir, "HoneyNetEvents_Clean.csv")
    brute_force_path = os.path.join(data_dir, "BruteForce_Clean.csv")

    logger.info("Loading CSV files…")

    df_all = pd.read_csv(honey_all_path)
    df_net = pd.read_csv(honey_net_path)
    _df = pd.concat([df_all, df_net], ignore_index=True)

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

    build_cache()


def ensure_data() -> None:
    if _df is None:
        load_data()


def ensure_brute_data() -> None:
    if _brute_df is None and not _data_loaded:
        load_data()


def safe_response(data: dict, **kwargs) -> tuple:
    response = {"success": True, "data": data}
    response.update(kwargs)
    return jsonify(response), 200


def safe_brute_response(data) -> tuple:
    return jsonify({"success": True, "data": data}), 200


# =============================================================================
# CACHE BUILDER — runs once after load_data()
# =============================================================================

def build_cache() -> None:
    """Pre-compute all aggregated API responses. Called once after CSV load."""
    global _cache, _cache_built

    if _cache_built:
        return

    logger.info("Building response cache…")

    # ── Overview ──────────────────────────────────────────────────────────────
    top_country_dict: dict[str, int] = {}
    if not _df["srcCountryName"].empty:
        top_entry = _df["srcCountryName"].value_counts().head(1)
        if not top_entry.empty:
            top_country_dict = {top_entry.index[0]: int(top_entry.iloc[0])}

    _cache["overview"] = {
        "totalEvents": len(_df),
        "uniqueSourceIPs": int(_df["srcIp"].nunique()),
        "uniqueDestinationIPs": int(_df["dstIp"].nunique()),
        "dateRange": {
            "start": _df["timestamp"].min().isoformat() if pd.notna(_df["timestamp"].min()) else None,
            "end":   _df["timestamp"].max().isoformat() if pd.notna(_df["timestamp"].max()) else None,
        },
        "protocols": int(_df["protocol"].nunique()),
        "attackTypes": int(_df["attackType"].nunique()),
        "countries": int(_df["srcCountryName"].nunique()),
        "topSourceCountry": top_country_dict,
    }

    # ── Trends (both groupings) ───────────────────────────────────────────────
    for group_by in ("day", "hour"):
        fmt = "%Y-%m-%d %H:00" if group_by == "hour" else "%Y-%m-%d"
        tg = _df["timestamp"].dt.strftime(fmt).rename("time_group")
        trends = tg.groupby(tg).size().reset_index(name="count").sort_values("time_group")
        _cache[f"trends_{group_by}"] = {
            "groupBy": group_by,
            "data": [
                {"time_group": str(r["time_group"]), "count": int(r["count"])}
                for r in trends.to_dict(orient="records")
            ],
        }

    # ── Attack types (full sorted list — routes slice to requested limit) ─────
    type_counts = _df["attackType"].value_counts().reset_index()
    type_counts.columns = ["type", "count"]
    type_counts["count"] = type_counts["count"].astype(int)
    _cache["types_all"] = {
        "data": type_counts.to_dict(orient="records"),
        "total": int(_df["attackType"].nunique()),
    }

    # ── Protocols ─────────────────────────────────────────────────────────────
    proto_counts = _df["protocol"].value_counts().reset_index()
    proto_counts.columns = ["protocol", "count"]
    proto_counts["count"] = proto_counts["count"].astype(int)
    _cache["protocols"] = {"data": proto_counts.to_dict(orient="records")}

    # ── Ports (full sorted list) ───────────────────────────────────────────────
    port_counts = _df["dstPort"].value_counts().reset_index()
    port_counts.columns = ["port", "count"]
    port_counts["port"] = port_counts["port"].astype(int)
    port_counts["count"] = port_counts["count"].astype(int)
    _cache["ports_all"] = {"data": port_counts.to_dict(orient="records")}

    # ── Countries (full sorted list) ──────────────────────────────────────────
    country_counts = _df["srcCountryName"].value_counts().reset_index()
    country_counts.columns = ["country", "count"]
    country_counts["count"] = country_counts["count"].astype(int)
    _cache["countries_all"] = {
        "data": country_counts.to_dict(orient="records"),
        "total": int(_df["srcCountryName"].nunique()),
    }

    # ── Heatmap ───────────────────────────────────────────────────────────────
    day_order = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
    hm = _df.groupby(["day_of_week", "hour_of_day"]).size().reset_index(name="count")
    hm_pivot = hm.pivot(index="day_of_week", columns="hour_of_day", values="count").fillna(0)
    hm_pivot = hm_pivot.reindex(day_order)
    hm_rows = []
    for day in day_order:
        row: dict[str, object] = {"day": day}
        if day in hm_pivot.index:
            for hour in range(24):
                row[str(hour)] = (
                    int(hm_pivot.loc[day, hour])
                    if hour in hm_pivot.columns and pd.notna(hm_pivot.loc[day, hour])
                    else 0
                )
        else:
            for hour in range(24):
                row[str(hour)] = 0
        hm_rows.append(row)
    _cache["heatmap"] = {"hours": list(range(24)), "days": day_order, "data": hm_rows}

    # ── Top sources (cache top-100; routes slice to requested limit) ──────────
    # Use drop_duplicates to build IP→meta lookup in O(N), not O(N*M)
    ip_meta = (
        _df.drop_duplicates("srcIp")
        .set_index("srcIp")[["srcCountryName", "srcOrg"]]
    )
    src_counts = _df["srcIp"].value_counts().head(100).reset_index()
    src_counts.columns = ["ip", "count"]
    src_counts["count"] = src_counts["count"].astype(int)
    top_src_records = []
    for _, r in src_counts.iterrows():
        ip = r["ip"]
        meta = ip_meta.loc[ip] if ip in ip_meta.index else None
        top_src_records.append({
            "ip": str(ip),
            "count": int(r["count"]),
            "country": str(meta["srcCountryName"]) if meta is not None else None,
            "org": (
                str(meta["srcOrg"])
                if meta is not None and pd.notna(meta["srcOrg"])
                else None
            ),
        })
    _cache["top_sources_all"] = {"data": top_src_records}

    # ── Geo map ───────────────────────────────────────────────────────────────
    geo = _df[["srcLat", "srcLon", "srcCountryName", "srcIp"]].copy()
    geo = geo.dropna(subset=["srcLat", "srcLon"])
    geo["count"] = geo.groupby(["srcLat", "srcLon"])["srcIp"].transform("count")
    geo = geo.drop_duplicates(subset=["srcLat", "srcLon"])
    geo = geo.sort_values("count", ascending=False).head(200)
    _cache["geo_map"] = {
        "data": [
            {
                "lat": float(r["srcLat"]),
                "lon": float(r["srcLon"]),
                "country": str(r["srcCountryName"]),
                "count": int(r["count"]),
            }
            for _, r in geo.iterrows()
        ]
    }

    # ── Brute force ───────────────────────────────────────────────────────────
    if _brute_df is not None and not _brute_df.empty:
        total = len(_brute_df)
        default_creds = int(_brute_df["is_default_credential"].sum())

        _cache["brute_summary"] = {
            "totalAttempts": total,
            "uniqueUsernames": int(_brute_df["username"].nunique()),
            "uniquePasswords": int(_brute_df["password"].nunique()),
            "uniqueIPs": int(_brute_df["src_ip"].nunique()),
            "defaultCredentialPct": round((default_creds / total) * 100, 2) if total > 0 else 0.0,
        }

        def _top(series, limit, col_name):
            t = series.value_counts().head(limit).reset_index()
            t.columns = [col_name, "count"]
            t["count"] = t["count"].astype(int)
            return t.to_dict(orient="records")

        _cache["brute_top_usernames"] = _top(_brute_df["username"], 20, "username")
        _cache["brute_top_passwords"] = _top(_brute_df["password"], 20, "password")

        top_pairs = (
            _brute_df.groupby(["username", "password"])
            .size().reset_index(name="count")
            .sort_values("count", ascending=False)
            .head(20)
        )
        top_pairs["count"] = top_pairs["count"].astype(int)
        _cache["brute_top_pairs"] = top_pairs.to_dict(orient="records")

        pt = _brute_df["password_type"].value_counts().reset_index()
        pt.columns = ["type", "count"]
        pt["count"] = pt["count"].astype(int)
        _cache["brute_password_types"] = pt.to_dict(orient="records")

        pl = _brute_df["password_length"].value_counts().sort_index().reset_index()
        pl.columns = ["length", "count"]
        pl["length"] = pl["length"].astype(int)
        pl["count"] = pl["count"].astype(int)
        _cache["brute_password_lengths"] = pl.to_dict(orient="records")

        _cache["brute_top_ips"] = _top(_brute_df["src_ip"], 20, "ip")

        tl = _brute_df.groupby("date_only").size().reset_index(name="count")
        tl.columns = ["date", "count"]
        tl["count"] = tl["count"].astype(int)
        tl = tl.sort_values("date")
        _cache["brute_timeline"] = tl.to_dict(orient="records")

    else:
        _cache["brute_summary"] = {
            "totalAttempts": 0, "uniqueUsernames": 0, "uniquePasswords": 0,
            "uniqueIPs": 0, "defaultCredentialPct": 0.0,
        }
        for key in ("brute_top_usernames", "brute_top_passwords", "brute_top_pairs",
                    "brute_password_types", "brute_password_lengths",
                    "brute_top_ips", "brute_timeline"):
            _cache[key] = []

    _cache_built = True
    logger.info("Cache built — all aggregations ready")


# =============================================================================
# HONEYPOT API ROUTES
# =============================================================================

@app.route("/api/overview", methods=["GET"])
@handle_errors
def get_overview():
    ensure_data()
    return safe_response(_cache["overview"])


@app.route("/api/trends", methods=["GET"])
@handle_errors
def get_trends():
    ensure_data()
    group_by = request.args.get("groupBy", "day")
    key = f"trends_{group_by}" if group_by in ("day", "hour") else "trends_day"
    return safe_response(_cache[key])


@app.route("/api/types", methods=["GET"])
@handle_errors
def get_types():
    ensure_data()
    limit = int(request.args.get("limit", 20))
    cached = _cache["types_all"]
    return safe_response({
        "data": cached["data"][:limit],
        "total": cached["total"],
    })


@app.route("/api/protocols", methods=["GET"])
@handle_errors
def get_protocols():
    ensure_data()
    return safe_response(_cache["protocols"])


@app.route("/api/ports", methods=["GET"])
@handle_errors
def get_ports():
    ensure_data()
    limit = int(request.args.get("limit", 15))
    return safe_response({"data": _cache["ports_all"]["data"][:limit]})


@app.route("/api/countries", methods=["GET"])
@handle_errors
def get_countries():
    ensure_data()
    limit = int(request.args.get("limit", 20))
    cached = _cache["countries_all"]
    return safe_response({
        "data": cached["data"][:limit],
        "total": cached["total"],
    })


@app.route("/api/heatmap", methods=["GET"])
@handle_errors
def get_heatmap():
    ensure_data()
    return safe_response(_cache["heatmap"])


@app.route("/api/details", methods=["GET"])
@handle_errors
def get_details():
    """Paginated + filtered event log. Not cached — dynamic query params."""
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
    ensure_data()
    limit = int(request.args.get("limit", 20))
    return safe_response({"data": _cache["top_sources_all"]["data"][:limit]})


@app.route("/api/geo-map", methods=["GET"])
@handle_errors
def get_geo_map():
    ensure_data()
    return safe_response(_cache["geo_map"])


@app.route("/api/health", methods=["GET"])
def health_check():
    return jsonify({
        "status": "healthy",
        "data_loaded": _data_loaded,
    })


# =============================================================================
# BRUTE FORCE API ROUTES
# =============================================================================

@app.route("/api/brute/summary", methods=["GET"])
@handle_errors
def get_brute_summary():
    ensure_brute_data()
    return safe_brute_response(_cache["brute_summary"])


@app.route("/api/brute/top-usernames", methods=["GET"])
@handle_errors
def get_brute_top_usernames():
    ensure_brute_data()
    return safe_brute_response(_cache["brute_top_usernames"])


@app.route("/api/brute/top-passwords", methods=["GET"])
@handle_errors
def get_brute_top_passwords():
    ensure_brute_data()
    return safe_brute_response(_cache["brute_top_passwords"])


@app.route("/api/brute/top-pairs", methods=["GET"])
@handle_errors
def get_brute_top_pairs():
    ensure_brute_data()
    return safe_brute_response(_cache["brute_top_pairs"])


@app.route("/api/brute/password-types", methods=["GET"])
@handle_errors
def get_brute_password_types():
    ensure_brute_data()
    return safe_brute_response(_cache["brute_password_types"])


@app.route("/api/brute/password-lengths", methods=["GET"])
@handle_errors
def get_brute_password_lengths():
    ensure_brute_data()
    return safe_brute_response(_cache["brute_password_lengths"])


@app.route("/api/brute/top-ips", methods=["GET"])
@handle_errors
def get_brute_top_ips():
    ensure_brute_data()
    return safe_brute_response(_cache["brute_top_ips"])


@app.route("/api/brute/timeline", methods=["GET"])
@handle_errors
def get_brute_timeline():
    ensure_brute_data()
    return safe_brute_response(_cache["brute_timeline"])


# =============================================================================
# MITRE ATT&CK DATA LOADING
# =============================================================================

def _parse_stix_bundle(objects: list) -> dict:
    """Parse STIX 2.1 objects into indexed dicts."""
    techniques: dict[str, dict] = {}
    mitigations: dict[str, dict] = {}
    stix_to_tech_ext: dict[str, str] = {}
    stix_to_mit_ext: dict[str, str] = {}
    tech_to_mit_stix: dict[str, list[str]] = {}

    for obj in objects:
        obj_type = obj.get("type", "")
        revoked = obj.get("revoked") or obj.get("x_mitre_deprecated")

        if obj_type == "attack-pattern" and not revoked:
            ext_id = next(
                (r["external_id"] for r in obj.get("external_references", [])
                 if r.get("source_name") == "mitre-attack" and r.get("external_id", "").startswith("T")),
                None,
            )
            if not ext_id:
                continue
            phase = next(
                (p["phase_name"] for p in obj.get("kill_chain_phases", [])
                 if p.get("kill_chain_name") == "mitre-attack"),
                None,
            )
            desc = obj.get("description", "")
            techniques[ext_id] = {
                "id": ext_id,
                "stix_id": obj["id"],
                "name": obj.get("name", ext_id),
                "description": desc[:400].rstrip() + ("…" if len(desc) > 400 else ""),
                "tactic": TACTIC_PHASE_TO_NAME.get(phase or "", phase or "Unknown"),
                "is_subtechnique": "." in ext_id,
            }
            stix_to_tech_ext[obj["id"]] = ext_id

        elif obj_type == "course-of-action" and not revoked:
            ext_id = next(
                (r["external_id"] for r in obj.get("external_references", [])
                 if r.get("source_name") == "mitre-attack" and r.get("external_id", "").startswith("M")),
                None,
            )
            if not ext_id:
                continue
            desc = obj.get("description", "")
            mitigations[ext_id] = {
                "id": ext_id,
                "stix_id": obj["id"],
                "name": obj.get("name", ext_id),
                "description": desc[:350].rstrip() + ("…" if len(desc) > 350 else ""),
            }
            stix_to_mit_ext[obj["id"]] = ext_id

    for obj in objects:
        if obj.get("type") == "relationship" and obj.get("relationship_type") == "mitigates":
            src = obj.get("source_ref", "")
            tgt = obj.get("target_ref", "")
            if src.startswith("course-of-action--") and tgt.startswith("attack-pattern--"):
                tech_to_mit_stix.setdefault(tgt, []).append(src)

    tech_to_mits: dict[str, list[str]] = {}
    for tech_stix_id, mit_stix_ids in tech_to_mit_stix.items():
        tech_ext = stix_to_tech_ext.get(tech_stix_id)
        if not tech_ext:
            continue
        tech_to_mits[tech_ext] = [
            stix_to_mit_ext[m] for m in mit_stix_ids if m in stix_to_mit_ext
        ]

    version = next(
        (obj.get("x_mitre_version", "unknown")
         for obj in objects if obj.get("type") == "x-mitre-collection"),
        "unknown",
    )

    return {
        "techniques": techniques,
        "mitigations": mitigations,
        "tech_to_mits": tech_to_mits,
        "version": version,
    }


def load_attack_data() -> None:
    """Fetch MITRE ATT&CK STIX bundle from GitHub (disk-cached). Thread-safe."""
    global _attack_data, _attack_loaded

    with _attack_lock:
        if _attack_loaded:
            return

        cache_path = os.path.join(os.path.dirname(__file__), "..", "data", "enterprise-attack.json")
        bundle_objects: list | None = None

        if os.path.exists(cache_path) and not os.environ.get("MITRE_REFRESH"):
            try:
                logger.info("Loading ATT&CK data from disk cache…")
                with open(cache_path, "r", encoding="utf-8") as f:
                    bundle_objects = json.load(f).get("objects", [])
                logger.info(f"Disk cache loaded: {len(bundle_objects)} objects")
            except Exception as e:
                logger.warning(f"Disk cache load failed ({e}), fetching from GitHub…")
                bundle_objects = None

        if bundle_objects is None:
            try:
                logger.info("Fetching ATT&CK STIX bundle from GitHub…")
                resp = http_requests.get(ATTACK_STIX_URL, timeout=60)
                resp.raise_for_status()
                bundle = resp.json()
                bundle_objects = bundle.get("objects", [])
                logger.info(f"Downloaded {len(bundle_objects)} STIX objects")
                try:
                    with open(cache_path, "w", encoding="utf-8") as f:
                        json.dump(bundle, f)
                    logger.info("ATT&CK bundle cached to disk")
                except Exception as e:
                    logger.warning(f"Failed to write disk cache: {e}")
            except Exception as e:
                logger.error(f"ATT&CK fetch failed: {e}. Proceeding without live data.")
                _attack_data = None
                _attack_loaded = True
                return

        try:
            _attack_data = _parse_stix_bundle(bundle_objects)
            logger.info(
                f"ATT&CK parsed: {len(_attack_data['techniques'])} techniques, "
                f"{len(_attack_data['mitigations'])} mitigations, "
                f"version {_attack_data['version']}"
            )
        except Exception as e:
            logger.error(f"ATT&CK parse failed: {e}")
            _attack_data = None
        finally:
            _attack_loaded = True


# =============================================================================
# THREAT MAPPING ENDPOINT
# =============================================================================

def _compute_severity(count: int) -> str:
    if count > 50000: return "CRITICAL"
    if count > 10000: return "HIGH"
    if count > 1000:  return "MEDIUM"
    return "LOW"


def _enrich_technique(tech_id: str, source: str, event_count: int) -> dict:
    sev = _compute_severity(event_count)
    base = {
        "id": tech_id,
        "source": source,
        "event_count": event_count,
        "severity": sev,
        "mitigations": [],
    }
    if _attack_data and tech_id in _attack_data["techniques"]:
        tech = _attack_data["techniques"][tech_id]
        mit_ids = _attack_data["tech_to_mits"].get(tech_id, [])[:4]
        base.update({
            "name": tech["name"],
            "description": tech["description"],
            "tactic": tech["tactic"],
            "mitigations": [
                {
                    "id": mid,
                    "name": _attack_data["mitigations"][mid]["name"],
                    "description": _attack_data["mitigations"][mid]["description"],
                }
                for mid in mit_ids if mid in _attack_data["mitigations"]
            ],
        })
    else:
        base.update({"name": tech_id, "description": "", "tactic": "Unknown"})
    return base


@app.route("/api/threat-mapping", methods=["GET"])
@handle_errors
def get_threat_mapping():
    """
    Returns MITRE ATT&CK technique mapping enriched with live STIX data.
    Uses cached type_counts to avoid recomputing value_counts on every call.
    """
    ensure_data()

    if not _attack_loaded:
        load_attack_data()

    # Use cached type counts instead of recomputing value_counts
    type_counts: dict[str, int] = {
        item["type"]: item["count"]
        for item in _cache.get("types_all", {}).get("data", [])
    }

    # Brute force summary from cache
    brute_summary_cached = _cache.get("brute_summary", {})
    brute_total = brute_summary_cached.get("totalAttempts", 0)
    brute_default_pct = brute_summary_cached.get("defaultCredentialPct", 0.0)
    brute_default_count = int(brute_default_pct / 100 * brute_total)

    technique_rows: list[dict] = []
    for source, tech_ids in SOURCE_TECHNIQUE_IDS.items():
        event_count = type_counts.get(source, 0)
        for tid in tech_ids:
            technique_rows.append(_enrich_technique(tid, source, event_count))

    brute_rows: list[dict] = []
    for bt in BRUTE_TECHNIQUE_IDS:
        count = brute_default_count if bt["count_source"] == "default" else brute_total
        row = _enrich_technique(bt["id"], "Brute Force", count)
        row["severity"] = bt["severity"]
        brute_rows.append(row)

    tactic_totals: dict[str, int] = {}
    for row in technique_rows + brute_rows:
        t = row["tactic"]
        tactic_totals[t] = tactic_totals.get(t, 0) + row["event_count"]

    all_sources = list(SOURCE_TECHNIQUE_IDS.keys()) + ["Brute Force"]
    active_tactics = list(dict.fromkeys(
        row["tactic"] for row in technique_rows + brute_rows if row["tactic"] != "Unknown"
    ))
    matrix: dict[str, dict[str, int]] = {s: {t: 0 for t in active_tactics} for s in all_sources}
    for row in technique_rows + brute_rows:
        if row["tactic"] in matrix.get(row["source"], {}):
            matrix[row["source"]][row["tactic"]] += row["event_count"]

    return safe_response({
        "attack_loaded": _attack_data is not None,
        "attack_version": _attack_data.get("version") if _attack_data else None,
        "techniques": technique_rows,
        "brute_techniques": brute_rows,
        "brute_summary": {
            "total_attempts": brute_total,
            "default_credential_pct": brute_default_pct,
        },
        "tactic_totals": tactic_totals,
        "all_tactics": ALL_TACTICS,
        "active_tactics": active_tactics,
        "matrix": matrix,
    })


# =============================================================================
# REPORT GENERATION
# =============================================================================

def _compute_report_stats(filters: dict) -> dict:
    """Compute filtered statistics for the report. Used by both preview and PDF."""
    ensure_data()

    dataset = filters.get("dataset", "both")
    attack_type = filters.get("attack_type", "all")
    country = filters.get("country", "all")
    protocol = filters.get("protocol", "all")
    password_type = filters.get("password_type", "all")
    default_only = filters.get("default_only", False)

    result = {
        "filters_applied": {
            "dataset": dataset,
            "attack_type": attack_type,
            "country": country,
            "protocol": protocol,
            "password_type": password_type,
            "default_only": default_only,
        },
        "generated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
    }

    # ── Honeynet section ─────────────────────────────────────────────────────
    if dataset in ("honeynet", "both") and _df is not None:
        df = _df
        if attack_type != "all":
            df = df[df["attackType"] == attack_type]
        if country != "all":
            df = df[df["srcCountryName"] == country]
        if protocol != "all":
            df = df[df["protocol"] == protocol]

        total = len(df)
        top_countries = df["srcCountryName"].value_counts().head(5)
        top_protocols = df["protocol"].value_counts().head(5)
        top_types = df["attackType"].value_counts().head(5)
        timeline = (
            df["timestamp"].dt.strftime("%Y-%m-%d")
            .value_counts().sort_index()
        )

        # Auto-generated summary
        summary = f"A total of {total:,} attack events were recorded matching the selected filters."
        if total > 0 and len(top_countries) > 0:
            tc_name = top_countries.index[0]
            tc_pct = round(int(top_countries.iloc[0]) / total * 100, 1)
            tp_name = top_protocols.index[0] if len(top_protocols) > 0 else "unknown"
            tt_name = top_types.index[0] if len(top_types) > 0 else "unknown"
            summary += (
                f" The majority of attacks originated from {tc_name} ({tc_pct}%),"
                f" primarily targeting {tp_name} services via the {tt_name} honeypot."
            )

        result["honeynet"] = {
            "total_events": total,
            "top_countries": [{"name": str(k), "count": int(v)} for k, v in top_countries.items()],
            "top_protocols": [{"name": str(k), "count": int(v)} for k, v in top_protocols.items()],
            "top_attack_types": [{"name": str(k), "count": int(v)} for k, v in top_types.items()],
            "timeline": [{"date": str(k), "count": int(v)} for k, v in timeline.items()],
            "summary": summary,
        }

    # ── Brute force section ──────────────────────────────────────────────────
    if dataset in ("brute_force", "both"):
        if _brute_df is not None and not _brute_df.empty:
            bdf = _brute_df
            if password_type != "all":
                bdf = bdf[bdf["password_type"] == password_type]
            if default_only:
                bdf = bdf[bdf["is_default_credential"] == True]  # noqa: E712

            total = len(bdf)
            unique_users = int(bdf["username"].nunique()) if total > 0 else 0
            unique_passes = int(bdf["password"].nunique()) if total > 0 else 0
            default_count = int(bdf["is_default_credential"].sum()) if total > 0 else 0
            default_pct = round((default_count / total) * 100, 2) if total > 0 else 0.0
            top_usernames = bdf["username"].value_counts().head(5)
            top_passwords = bdf["password"].value_counts().head(5)
            pw_types = bdf["password_type"].value_counts()

            summary = f"A total of {total:,} credential brute force attempts were recorded."
            if total > 0 and len(top_usernames) > 0:
                tu = top_usernames.index[0]
                tu_pct = round(int(top_usernames.iloc[0]) / total * 100, 1)
                summary += (
                    f" {unique_users:,} unique usernames and {unique_passes:,} unique passwords were observed."
                    f" The most targeted username was '{tu}' ({tu_pct}% of attempts)."
                    f" {default_pct}% of attempts used default credentials."
                )

            result["brute_force"] = {
                "total_attempts": total,
                "unique_usernames": unique_users,
                "unique_passwords": unique_passes,
                "default_credential_pct": default_pct,
                "top_usernames": [{"name": str(k), "count": int(v)} for k, v in top_usernames.items()],
                "top_passwords": [{"name": str(k), "count": int(v)} for k, v in top_passwords.items()],
                "password_type_distribution": [{"type": str(k), "count": int(v)} for k, v in pw_types.items()],
                "summary": summary,
            }
        else:
            result["brute_force"] = {
                "total_attempts": 0, "unique_usernames": 0, "unique_passwords": 0,
                "default_credential_pct": 0, "top_usernames": [], "top_passwords": [],
                "password_type_distribution": [], "summary": "No brute force data available.",
            }

    return result


def _build_report_html(stats: dict) -> str:
    """Build an inline-styled HTML report for PDF rendering."""
    filters = stats.get("filters_applied", {})
    generated = stats.get("generated_at", "")

    # Helper: build a two-column table from a list of {name, count} dicts
    def _table(rows, col1="Name", col2="Count"):
        if not rows:
            return '<p style="color:#999;font-size:13px;">No data available</p>'
        trs = ""
        for i, r in enumerate(rows):
            bg = "#f8f7ff" if i % 2 == 0 else "#fff"
            name_key = "name" if "name" in r else "type"
            trs += (
                f'<tr style="background:{bg};">'
                f'<td style="padding:8px 12px;border-bottom:1px solid #eee;">{r[name_key]}</td>'
                f'<td style="padding:8px 12px;border-bottom:1px solid #eee;text-align:right;font-weight:600;">'
                f'{r["count"]:,}</td></tr>'
            )
        return (
            f'<table style="width:100%;border-collapse:collapse;font-size:13px;margin-top:8px;">'
            f'<thead><tr style="background:#6d28d9;color:#fff;">'
            f'<th style="padding:8px 12px;text-align:left;">{col1}</th>'
            f'<th style="padding:8px 12px;text-align:right;">{col2}</th>'
            f'</tr></thead><tbody>{trs}</tbody></table>'
        )

    # Filter summary rows
    filter_rows = "".join(
        f'<tr><td style="padding:4px 12px 4px 0;color:#666;font-weight:600;">{k.replace("_", " ").title()}</td>'
        f'<td style="padding:4px 0;color:#333;">{v}</td></tr>'
        for k, v in filters.items()
    )

    # Build sections
    honeynet_html = ""
    if "honeynet" in stats:
        h = stats["honeynet"]
        honeynet_html = f"""
        <div style="margin-bottom:32px;">
            <h2 style="color:#6d28d9;font-size:20px;border-bottom:2px solid #6d28d9;padding-bottom:8px;">
                Honeynet Attack Analysis
            </h2>
            <div style="background:#f0ecff;border-radius:8px;padding:16px;margin:16px 0;">
                <span style="font-size:32px;font-weight:700;color:#1a1a2e;">{h['total_events']:,}</span>
                <span style="color:#666;font-size:14px;margin-left:8px;">total attack events</span>
            </div>
            <p style="color:#444;font-size:14px;line-height:1.6;margin:16px 0;background:#fffbf0;border-left:4px solid #f59e0b;padding:12px 16px;border-radius:0 8px 8px 0;">
                {h['summary']}
            </p>
            <div style="display:flex;gap:16px;flex-wrap:wrap;">
                <div style="flex:1;min-width:200px;">
                    <h4 style="color:#333;font-size:14px;margin-bottom:4px;">Top Countries</h4>
                    {_table(h['top_countries'], 'Country', 'Events')}
                </div>
                <div style="flex:1;min-width:200px;">
                    <h4 style="color:#333;font-size:14px;margin-bottom:4px;">Top Protocols</h4>
                    {_table(h['top_protocols'], 'Protocol', 'Events')}
                </div>
            </div>
            <div style="margin-top:16px;">
                <h4 style="color:#333;font-size:14px;margin-bottom:4px;">Top Attack Types</h4>
                {_table(h['top_attack_types'], 'Attack Type', 'Events')}
            </div>
        </div>"""

    brute_html = ""
    if "brute_force" in stats:
        b = stats["brute_force"]
        pw_type_table = _table(b.get("password_type_distribution", []), "Type", "Count")
        brute_html = f"""
        <div style="margin-bottom:32px;">
            <h2 style="color:#6d28d9;font-size:20px;border-bottom:2px solid #6d28d9;padding-bottom:8px;">
                Brute Force Intelligence
            </h2>
            <div style="display:flex;gap:12px;flex-wrap:wrap;margin:16px 0;">
                <div style="flex:1;min-width:140px;background:#f0ecff;border-radius:8px;padding:14px;text-align:center;">
                    <div style="font-size:24px;font-weight:700;color:#1a1a2e;">{b['total_attempts']:,}</div>
                    <div style="color:#666;font-size:12px;">Total Attempts</div>
                </div>
                <div style="flex:1;min-width:140px;background:#f0ecff;border-radius:8px;padding:14px;text-align:center;">
                    <div style="font-size:24px;font-weight:700;color:#1a1a2e;">{b['unique_usernames']:,}</div>
                    <div style="color:#666;font-size:12px;">Unique Usernames</div>
                </div>
                <div style="flex:1;min-width:140px;background:#f0ecff;border-radius:8px;padding:14px;text-align:center;">
                    <div style="font-size:24px;font-weight:700;color:#1a1a2e;">{b['unique_passwords']:,}</div>
                    <div style="color:#666;font-size:12px;">Unique Passwords</div>
                </div>
                <div style="flex:1;min-width:140px;background:#fff0f0;border-radius:8px;padding:14px;text-align:center;">
                    <div style="font-size:24px;font-weight:700;color:#dc2626;">{b['default_credential_pct']}%</div>
                    <div style="color:#666;font-size:12px;">Default Credentials</div>
                </div>
            </div>
            <p style="color:#444;font-size:14px;line-height:1.6;margin:16px 0;background:#fffbf0;border-left:4px solid #f59e0b;padding:12px 16px;border-radius:0 8px 8px 0;">
                {b['summary']}
            </p>
            <div style="display:flex;gap:16px;flex-wrap:wrap;">
                <div style="flex:1;min-width:200px;">
                    <h4 style="color:#333;font-size:14px;margin-bottom:4px;">Top Usernames</h4>
                    {_table(b['top_usernames'], 'Username', 'Attempts')}
                </div>
                <div style="flex:1;min-width:200px;">
                    <h4 style="color:#333;font-size:14px;margin-bottom:4px;">Top Passwords</h4>
                    {_table(b['top_passwords'], 'Password', 'Attempts')}
                </div>
            </div>
            <div style="margin-top:16px;">
                <h4 style="color:#333;font-size:14px;margin-bottom:4px;">Password Type Distribution</h4>
                {pw_type_table}
            </div>
        </div>"""

    html = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Cyber Attack Intelligence Report</title></head>
<body style="font-family:'Segoe UI',Arial,sans-serif;background:#fff;color:#1a1a2e;max-width:800px;margin:0 auto;padding:40px;">
    <div style="text-align:center;border-bottom:3px solid #6d28d9;padding-bottom:20px;margin-bottom:30px;">
        <h1 style="color:#1a1a2e;margin:0;font-size:26px;">Cyber Attack Intelligence Report</h1>
        <p style="color:#888;margin-top:8px;font-size:13px;">Generated: {generated}</p>
    </div>
    <div style="background:#f8f7ff;border:1px solid #e0dff5;border-radius:8px;padding:16px;margin-bottom:28px;">
        <h3 style="margin:0 0 10px;color:#6d28d9;font-size:14px;">Report Filters Applied</h3>
        <table style="font-size:13px;color:#444;">{filter_rows}</table>
    </div>
    {honeynet_html}
    {brute_html}
    <div style="text-align:center;border-top:2px solid #eee;padding-top:20px;margin-top:40px;color:#999;font-size:11px;">
        Generated by Cyber Attack Intelligence Visualization Platform
    </div>
</body>
</html>"""
    return html


@app.route("/api/report-preview", methods=["GET"])
@handle_errors
def get_report_preview():
    """Return report statistics as JSON (for the in-page preview)."""
    filters = {
        "dataset": request.args.get("dataset", "both"),
        "attack_type": request.args.get("attack_type", "all"),
        "country": request.args.get("country", "all"),
        "protocol": request.args.get("protocol", "all"),
        "password_type": request.args.get("password_type", "all"),
        "default_only": request.args.get("default_only", "false").lower() == "true",
    }
    stats = _compute_report_stats(filters)
    return safe_response(stats)


@app.route("/api/generate-report", methods=["POST"])
@handle_errors
def generate_report():
    """Generate a PDF report and return as downloadable file."""
    from weasyprint import HTML

    body = request.get_json(force=True, silent=True) or {}
    filters = {
        "dataset": body.get("dataset", "both"),
        "attack_type": body.get("attack_type", "all"),
        "country": body.get("country", "all"),
        "protocol": body.get("protocol", "all"),
        "password_type": body.get("password_type", "all"),
        "default_only": bool(body.get("default_only", False)),
    }
    stats = _compute_report_stats(filters)
    html_content = _build_report_html(stats)
    pdf = HTML(string=html_content).write_pdf()

    response = make_response(pdf)
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = "attachment; filename=cyber_attack_report.pdf"
    return response


if __name__ == "__main__":
    load_data()   # also calls build_cache()
    app.run(host="0.0.0.0", port=5000, debug=True)
