import calendar
import csv
import hmac
import io
import ipaddress
import json
import os
import random
import secrets
import smtplib
import sys
from datetime import datetime, timedelta
from email.message import EmailMessage
from functools import wraps

import joblib
import pandas as pd
import psutil
from apscheduler.schedulers.background import BackgroundScheduler
from flask import (
    Flask,
    jsonify,
    has_request_context,
    request,
    send_file,
    send_from_directory,
    session,
)
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from sqlalchemy import inspect, or_, text
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None

try:
    from flask_socketio import SocketIO, emit
except ImportError:
    SocketIO = None
    emit = None


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.abspath(os.path.join(BASE_DIR, ".."))
AI_ENGINE_DIR = os.path.join(PROJECT_DIR, "ai_engine")
FRONTEND_BUILD_DIR = os.path.join(PROJECT_DIR, "frontend", "build")

if load_dotenv:
    load_dotenv(os.path.join(PROJECT_DIR, ".env"))

REPORT_DIR = os.getenv("EVOGUARD_REPORT_DIR", os.path.join(BASE_DIR, "reports"))

if not os.path.isabs(REPORT_DIR):
    REPORT_DIR = os.path.abspath(os.path.join(PROJECT_DIR, REPORT_DIR))

sys.path.insert(0, AI_ENGINE_DIR)

from agentic_ai import agentic_analysis


MODEL_PATH = os.path.join(AI_ENGINE_DIR, "evoguard_optimized_model.pkl")
ENCODER_PATH = os.path.join(AI_ENGINE_DIR, "label_encoders.pkl")
FEATURE_PATH = os.path.join(AI_ENGINE_DIR, "selected_features.pkl")
METRICS_PATH = os.path.join(AI_ENGINE_DIR, "model_metrics.json")

AVAILABLE_ATTACK_TYPES = ["dos", "probe", "r2l", "u2r", "normal"]
DEFAULT_ANALYST_EMAIL = os.getenv("EVOGUARD_ANALYST_EMAIL", "evoguardzu@gmail.com")
DEFAULT_ADMIN_USERNAME = os.getenv("EVOGUARD_DEFAULT_USERNAME", "").strip()
DEFAULT_ADMIN_PASSWORD = os.getenv("EVOGUARD_DEFAULT_PASSWORD", "")
INGEST_API_KEY = os.getenv("EVOGUARD_INGEST_API_KEY", "")
USER_ROLES = {
    "Admin": {
        "access_level": "Administrator",
        "description": "Full EvoGuard control, including user management and system resets.",
    },
    "SOC Analyst": {
        "access_level": "Operator",
        "description": "Can monitor threats, use live intake, run simulations, and generate reports.",
    },
    "Viewer": {
        "access_level": "Read Only",
        "description": "Can view dashboards and reports without changing system data.",
    },
}
DEFAULT_CORS_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "https://mayedalshehhi.github.io",
]
VALID_REPORT_TYPES = {
    "incident": "Incident",
    "weekly": "Weekly",
    "monthly": "Monthly",
    "yearly": "Yearly",
}

LIVE_EVENT_ALIASES = {
    "dos": "neptune",
    "ddos": "neptune",
    "flood": "neptune",
    "tcp flood": "neptune",
    "probe": "satan",
    "scan": "satan",
    "port scan": "satan",
    "recon": "satan",
    "r2l": "guess_passwd",
    "credential": "guess_passwd",
    "bruteforce": "guess_passwd",
    "password": "guess_passwd",
    "login attack": "guess_passwd",
    "u2r": "buffer_overflow",
    "privilege": "buffer_overflow",
    "privilege escalation": "buffer_overflow",
    "root": "buffer_overflow",
    "normal": "normal",
    "benign": "normal",
}

AI_RESPONSE_PLAYBOOK = {
    "dos": {
        "name": "Availability Protection Playbook",
        "objective": "Preserve service availability during flood or denial-of-service behavior.",
        "automation_level": "Full autonomous containment",
        "actions": [
            {
                "action_name": "Block attacking source",
                "action_type": "firewall_block",
                "explanation": "Block high-volume traffic from the malicious source IP.",
                "impact": "Stops the most visible abusive flow at the perimeter.",
            },
            {
                "action_name": "Apply adaptive rate limit",
                "action_type": "rate_limit",
                "explanation": "Reduce request pressure on protected services.",
                "impact": "Keeps legitimate traffic available while limiting burst abuse.",
            },
            {
                "action_name": "Activate DDoS shield",
                "action_type": "traffic_scrubbing",
                "explanation": "Route suspicious flow patterns through mitigation controls.",
                "impact": "Moves traffic into a simulated scrubbing workflow.",
            },
            {
                "action_name": "Monitor service availability",
                "action_type": "availability_monitor",
                "explanation": "Continue watching latency and service stability.",
                "impact": "Confirms whether containment is holding.",
            },
        ],
    },
    "probe": {
        "name": "Reconnaissance Suppression Playbook",
        "objective": "Reduce attacker visibility into exposed services and ports.",
        "automation_level": "Autonomous mitigation with monitoring",
        "actions": [
            {
                "action_name": "Throttle scanner traffic",
                "action_type": "traffic_throttle",
                "explanation": "Slow reconnaissance activity while preserving service availability.",
                "impact": "Reduces scan speed and attacker feedback.",
            },
            {
                "action_name": "Deploy scan detection rule",
                "action_type": "ids_rule",
                "explanation": "Create a temporary detection rule for repeated probe behavior.",
                "impact": "Raises detection coverage for similar activity.",
            },
            {
                "action_name": "Harden exposed services",
                "action_type": "surface_reduction",
                "explanation": "Increase monitoring around scanned ports and exposed services.",
                "impact": "Reduces exposed attack surface in the prototype workflow.",
            },
            {
                "action_name": "Add source to AI watchlist",
                "action_type": "watchlist",
                "explanation": "Track recurring behavior from the same source.",
                "impact": "Improves future prioritization for repeated sources.",
            },
        ],
    },
    "r2l": {
        "name": "Identity Containment Playbook",
        "objective": "Contain unauthorized remote access and credential misuse.",
        "automation_level": "Autonomous identity defense",
        "actions": [
            {
                "action_name": "Block suspicious remote session",
                "action_type": "session_block",
                "explanation": "Terminate unauthorized remote access behavior.",
                "impact": "Stops the active remote access attempt.",
            },
            {
                "action_name": "Trigger adaptive authentication",
                "action_type": "identity_control",
                "explanation": "Increase identity challenge level for targeted accounts.",
                "impact": "Forces stronger verification on risky access paths.",
            },
            {
                "action_name": "Lock targeted account window",
                "action_type": "account_lock",
                "explanation": "Temporarily restrict accounts showing compromise indicators.",
                "impact": "Reduces account takeover risk.",
            },
            {
                "action_name": "Monitor credential replay",
                "action_type": "identity_monitor",
                "explanation": "Watch for repeated authentication attempts.",
                "impact": "Keeps the AI response in monitoring mode after containment.",
            },
        ],
    },
    "u2r": {
        "name": "Privilege Escalation Containment Playbook",
        "objective": "Stop root-level escalation paths and preserve evidence.",
        "automation_level": "Full autonomous host containment",
        "actions": [
            {
                "action_name": "Isolate suspicious endpoint",
                "action_type": "endpoint_isolation",
                "explanation": "Contain host activity that suggests privilege escalation.",
                "impact": "Prevents lateral movement from the suspicious endpoint.",
            },
            {
                "action_name": "Terminate elevated process",
                "action_type": "process_control",
                "explanation": "Stop suspicious elevated execution attempts.",
                "impact": "Interrupts the privilege escalation sequence.",
            },
            {
                "action_name": "Revoke risky privilege path",
                "action_type": "privilege_control",
                "explanation": "Restrict the privilege path used by the attacker.",
                "impact": "Reduces chance of root-level control.",
            },
            {
                "action_name": "Capture forensic snapshot",
                "action_type": "forensics",
                "explanation": "Preserve system evidence for later investigation.",
                "impact": "Creates evidence for post-incident review.",
            },
        ],
    },
    "normal": {
        "name": "Benign Telemetry Baseline Playbook",
        "objective": "Avoid unnecessary disruption while improving normal traffic baselines.",
        "automation_level": "Monitoring only",
        "actions": [
            {
                "action_name": "Store baseline telemetry",
                "action_type": "baseline_learning",
                "explanation": "Save event shape as normal behavior for future comparison.",
                "impact": "Improves baseline awareness without defensive disruption.",
            },
            {
                "action_name": "Continue passive monitoring",
                "action_type": "passive_monitor",
                "explanation": "No defensive disruption required for benign traffic.",
                "impact": "Keeps the event under observation.",
            },
        ],
    },
}

LIVE_TEST_EVENT_LIBRARY = {
    "dos": [
        {
            "attack_label": "ddos",
            "country": "Russia",
            "source_activity": "High-volume TCP flood targeting public service",
        },
        {
            "attack_label": "tcp flood",
            "country": "Brazil",
            "source_activity": "Botnet traffic spike against protected endpoint",
        },
    ],
    "probe": [
        {
            "attack_label": "probe scan",
            "country": "China",
            "source_activity": "Repeated port scanning across exposed services",
        },
        {
            "attack_label": "nmap",
            "country": "India",
            "source_activity": "Reconnaissance scan detected on perimeter services",
        },
    ],
    "r2l": [
        {
            "attack_label": "credential attack",
            "country": "Germany",
            "source_activity": "Repeated suspicious login attempts",
        },
        {
            "attack_label": "r2l",
            "country": "USA",
            "source_activity": "Unauthorized remote access behavior detected",
        },
    ],
    "u2r": [
        {
            "attack_label": "privilege escalation",
            "country": "Iran",
            "source_activity": "Possible privilege escalation sequence",
        },
        {
            "attack_label": "rootkit",
            "country": "North Korea",
            "source_activity": "Root-level behavior observed on monitored host",
        },
    ],
    "normal": [
        {
            "attack_label": "normal",
            "country": "UAE",
            "source_activity": "Normal baseline network traffic",
        },
    ],
}

MITRE_ATTACK_MAPPING = {
    "dos": {
        "technique": "T1498 - Network Denial of Service",
        "tactic": "Impact",
        "priority": "Protect service availability and absorb traffic pressure.",
    },
    "probe": {
        "technique": "T1046 - Network Service Discovery",
        "tactic": "Discovery",
        "priority": "Reduce exposed attack surface and watch repeat scanning.",
    },
    "r2l": {
        "technique": "T1110 - Brute Force",
        "tactic": "Credential Access",
        "priority": "Contain identity abuse and block unauthorized sessions.",
    },
    "u2r": {
        "technique": "T1068 - Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "priority": "Isolate endpoint and stop elevated execution paths.",
    },
    "normal": {
        "technique": "T1030 - Data Transfer Size Limits",
        "tactic": "Benign Baseline",
        "priority": "Keep as baseline telemetry unless behavior changes.",
    },
}

THREAT_REPUTATION_WEIGHTS = {
    "Malicious": 14,
    "Critical": 12,
    "High Risk": 9,
    "High Impact": 8,
    "Suspicious": 7,
    "Watchlist": 4,
    "Elevated": 3,
    "Benign": -8,
    "Trusted": -10,
}

DEFAULT_THREAT_IOCS = [
    {
        "indicator_type": "ip",
        "indicator_value": "203.0.113.77",
        "reputation": "Malicious",
        "confidence": 94,
        "attack_category": "dos",
        "source_name": "EvoGuard Lab IOC",
        "notes": "Repeated high-volume TCP flood source used in live intake tests.",
    },
    {
        "indicator_type": "ip",
        "indicator_value": "198.51.100.23",
        "reputation": "Suspicious",
        "confidence": 86,
        "attack_category": "probe",
        "source_name": "EvoGuard Lab IOC",
        "notes": "Reconnaissance and service discovery source.",
    },
    {
        "indicator_type": "ip",
        "indicator_value": "198.51.100.44",
        "reputation": "High Risk",
        "confidence": 88,
        "attack_category": "r2l",
        "source_name": "EvoGuard Lab IOC",
        "notes": "Credential attack source with repeated remote login behavior.",
    },
    {
        "indicator_type": "ip",
        "indicator_value": "203.0.113.91",
        "reputation": "Critical",
        "confidence": 96,
        "attack_category": "u2r",
        "source_name": "EvoGuard Lab IOC",
        "notes": "Privilege escalation source requiring immediate containment.",
    },
    {
        "indicator_type": "country",
        "indicator_value": "Russia",
        "reputation": "Watchlist",
        "confidence": 72,
        "attack_category": "dos",
        "source_name": "EvoGuard Geo Intel",
        "notes": "Elevated DDoS volume in current lab profile.",
    },
    {
        "indicator_type": "country",
        "indicator_value": "China",
        "reputation": "Watchlist",
        "confidence": 70,
        "attack_category": "probe",
        "source_name": "EvoGuard Geo Intel",
        "notes": "Repeated reconnaissance pattern in current lab profile.",
    },
    {
        "indicator_type": "country",
        "indicator_value": "North Korea",
        "reputation": "High Risk",
        "confidence": 90,
        "attack_category": "u2r",
        "source_name": "EvoGuard Geo Intel",
        "notes": "High-priority intrusion source in current lab profile.",
    },
    {
        "indicator_type": "attack_category",
        "indicator_value": "u2r",
        "reputation": "High Impact",
        "confidence": 92,
        "attack_category": "u2r",
        "source_name": "MITRE ATT&CK Mapping",
        "notes": "Privilege escalation events receive priority enrichment.",
    },
]

db = SQLAlchemy()
socketio = SocketIO(async_mode="threading") if SocketIO else None
ACTIVE_SOCKET_CLIENTS = set()
socket_handlers_registered = False


def configured_cors_origins():
    raw_origins = os.getenv("EVOGUARD_CORS_ORIGIN", "").strip()

    if not raw_origins:
        return DEFAULT_CORS_ORIGINS

    origins = [
        origin.strip()
        for origin in raw_origins.split(",")
        if origin.strip()
    ]

    if not origins or origins == ["*"]:
        return DEFAULT_CORS_ORIGINS

    return origins


def env_bool(name, default=False):
    value = os.getenv(name)

    if value is None:
        return default

    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_int(name, default, minimum=None, maximum=None):
    try:
        value = int(os.getenv(name, default))
    except (TypeError, ValueError):
        value = default

    if minimum is not None:
        value = max(minimum, value)

    if maximum is not None:
        value = min(maximum, value)

    return value


def configured_database_uri():
    database_url = os.getenv("EVOGUARD_DATABASE_URL", "sqlite:///evoguard.db")

    if database_url.startswith("postgres://"):
        return database_url.replace("postgres://", "postgresql://", 1)

    return database_url


def load_secret_key():
    configured_secret = os.getenv("EVOGUARD_SECRET_KEY", "").strip()

    if configured_secret and configured_secret != "change-this-secret":
        return configured_secret

    secret_path = os.path.join(BASE_DIR, "instance", "secret.key")

    try:
        if os.path.exists(secret_path):
            with open(secret_path, "r", encoding="utf-8") as file:
                saved_secret = file.read().strip()

            if saved_secret:
                return saved_secret

        os.makedirs(os.path.dirname(secret_path), exist_ok=True)
        generated_secret = secrets.token_urlsafe(48)

        with open(secret_path, "w", encoding="utf-8") as file:
            file.write(generated_secret)

        return generated_secret
    except OSError:
        return secrets.token_urlsafe(48)


def normalize_report_type(report_type):
    key = str(report_type or "Incident").strip().lower()

    if key not in VALID_REPORT_TYPES:
        raise ValueError(
            f"Invalid report type. Allowed values: {', '.join(VALID_REPORT_TYPES.values())}."
        )

    return VALID_REPORT_TYPES[key]


class AttackLog(db.Model):
    __tablename__ = "attack_log"
    __table_args__ = (
        db.Index("ix_attack_log_source_time", "event_source", "timestamp"),
        db.Index("ix_attack_log_risk_time", "risk_level", "timestamp"),
        db.Index("ix_attack_log_type_time", "attack_type", "timestamp"),
        db.Index("ix_attack_log_source_ip_time", "source_ip", "timestamp"),
    )

    id = db.Column(db.Integer, primary_key=True)
    event_uuid = db.Column(db.String(80), unique=True, index=True)
    attack_label = db.Column(db.String(100))
    attack_category = db.Column(db.String(100))
    attack_type = db.Column(db.String(40), index=True)
    risk_score = db.Column(db.Integer)
    risk_level = db.Column(db.String(50))
    explanation = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    event_source = db.Column(db.String(50), default="simulation", nullable=False)
    event_status = db.Column(db.String(60), default="analyzed", nullable=False)
    source_country = db.Column(db.String(100))
    source_ip = db.Column(db.String(64))
    source_activity = db.Column(db.String(120))
    raw_payload = db.Column(db.Text)
    sensor_name = db.Column(db.String(120))
    target_asset = db.Column(db.String(140))
    network_protocol = db.Column(db.String(20))
    destination_port = db.Column(db.Integer)
    response_mode = db.Column(db.String(120))
    response_confidence = db.Column(db.Float)
    intel_reputation = db.Column(db.String(80))
    intel_confidence = db.Column(db.Float)
    intel_score = db.Column(db.Integer)
    intel_summary = db.Column(db.Text)
    mitre_technique = db.Column(db.String(160))
    mitre_tactic = db.Column(db.String(100))
    ioc_matches = db.Column(db.Text)
    created_by_user_id = db.Column(db.Integer, db.ForeignKey("evoguard_user.id"))


class AIResponseLog(db.Model):
    __tablename__ = "ai_response_log"
    __table_args__ = (
        db.Index("ix_ai_response_attack_time", "attack_id", "timestamp"),
        db.Index("ix_ai_response_status_time", "status", "timestamp"),
    )

    id = db.Column(db.Integer, primary_key=True)
    attack_id = db.Column(db.Integer, db.ForeignKey("attack_log.id"), nullable=False)
    action_name = db.Column(db.String(140), nullable=False)
    action_type = db.Column(db.String(80), nullable=False)
    execution_stage = db.Column(db.String(80), nullable=False)
    status = db.Column(db.String(50), nullable=False)
    confidence = db.Column(db.Float)
    explanation = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class User(db.Model):
    __tablename__ = "evoguard_user"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(80), default="SOC Analyst")
    access_level = db.Column(db.String(80), default="Administrator")
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)


class ThreatIntelIOC(db.Model):
    __tablename__ = "threat_intel_ioc"
    __table_args__ = (
        db.Index("ix_ioc_type_value", "indicator_type", "indicator_value"),
        db.Index("ix_ioc_reputation_confidence", "reputation", "confidence"),
    )

    id = db.Column(db.Integer, primary_key=True)
    indicator_type = db.Column(db.String(50), nullable=False)
    indicator_value = db.Column(db.String(140), nullable=False)
    reputation = db.Column(db.String(80), nullable=False)
    confidence = db.Column(db.Float, default=70)
    attack_category = db.Column(db.String(100))
    source_name = db.Column(db.String(120), default="EvoGuard Threat Intel")
    notes = db.Column(db.Text)
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    sightings = db.Column(db.Integer, default=0)


class SystemAuditLog(db.Model):
    __tablename__ = "system_audit_log"
    __table_args__ = (
        db.Index("ix_audit_action_time", "action", "timestamp"),
        db.Index("ix_audit_entity_time", "entity_type", "entity_id", "timestamp"),
    )

    id = db.Column(db.Integer, primary_key=True)
    actor_user_id = db.Column(db.Integer, db.ForeignKey("evoguard_user.id"))
    actor_username = db.Column(db.String(80), default="system")
    action = db.Column(db.String(120), nullable=False)
    entity_type = db.Column(db.String(80))
    entity_id = db.Column(db.Integer)
    event_source = db.Column(db.String(50))
    ip_address = db.Column(db.String(64))
    user_agent = db.Column(db.String(255))
    details = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class ReportGenerationLog(db.Model):
    __tablename__ = "report_generation_log"
    __table_args__ = (
        db.Index("ix_report_type_time", "report_type", "generated_at"),
        db.Index("ix_report_status_time", "delivery_status", "generated_at"),
    )

    id = db.Column(db.Integer, primary_key=True)
    report_type = db.Column(db.String(50), nullable=False)
    delivery_method = db.Column(db.String(50), default="download")
    delivery_status = db.Column(db.String(50), default="generated")
    filename = db.Column(db.String(255))
    recipient = db.Column(db.String(140))
    generated_by_user_id = db.Column(db.Integer, db.ForeignKey("evoguard_user.id"))
    generated_at = db.Column(db.DateTime, default=datetime.utcnow)
    summary_json = db.Column(db.Text)


def create_app():
    app = Flask(__name__, static_folder=None)
    app.secret_key = load_secret_key()
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE=os.getenv("EVOGUARD_COOKIE_SAMESITE", "Lax"),
        SESSION_COOKIE_SECURE=env_bool("EVOGUARD_COOKIE_SECURE", False),
        MAX_CONTENT_LENGTH=env_int("EVOGUARD_MAX_UPLOAD_MB", 8, minimum=1, maximum=64)
        * 1024
        * 1024,
    )

    cors_origins = configured_cors_origins()
    CORS(app, resources={r"/*": {"origins": cors_origins}}, supports_credentials=True)

    app.config["SQLALCHEMY_DATABASE_URI"] = configured_database_uri()
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    db.init_app(app)

    if socketio:
        socketio.init_app(app, cors_allowed_origins=cors_origins)

    register_routes(app)
    register_error_handlers(app)
    register_security_headers(app)
    register_socket_handlers()

    return app


def load_ai_artifacts():
    missing = [
        path
        for path in [MODEL_PATH, ENCODER_PATH, FEATURE_PATH]
        if not os.path.exists(path)
    ]

    if missing:
        raise FileNotFoundError(f"Missing AI artifact(s): {', '.join(missing)}")

    return {
        "model": joblib.load(MODEL_PATH),
        "label_encoders": joblib.load(ENCODER_PATH),
        "selected_features": joblib.load(FEATURE_PATH),
    }


AI = load_ai_artifacts()

def format_metric_percent(value):
    if value is None:
        return "Pending"

    try:
        numeric_value = float(value)
    except (TypeError, ValueError):
        return "Pending"

    if numeric_value <= 1:
        numeric_value *= 100

    return f"{numeric_value:.2f}%"


def load_model_metrics():
    default_metrics = {
        "accuracy": None,
        "accuracy_display": "Pending",
        "precision": None,
        "recall": None,
        "f1_score": None,
        "dataset": "NSL-KDD",
        "model": "RandomForestClassifier",
        "last_trained": "Not recorded",
        "selected_features_count": len(AI["selected_features"]),
        "metric_source": "not_available",
    }

    if not os.path.exists(METRICS_PATH):
        return default_metrics

    try:
        with open(METRICS_PATH, "r", encoding="utf-8-sig") as file:
            metrics = json.load(file)
    except (OSError, json.JSONDecodeError):
        return default_metrics

    merged_metrics = {**default_metrics, **metrics}
    merged_metrics["accuracy_display"] = (
        merged_metrics.get("accuracy_display")
        or format_metric_percent(merged_metrics.get("accuracy"))
    )

    return merged_metrics


def api_error(message, status=400, **extra):
    payload = {"status": "error", "message": message}
    payload.update(extra)
    return jsonify(payload), status


def desktop_frontend_enabled():
    return env_bool("EVOGUARD_SERVE_FRONTEND", False) and os.path.exists(
        os.path.join(FRONTEND_BUILD_DIR, "index.html")
    )


def serve_frontend_asset(asset_path="index.html"):
    if not desktop_frontend_enabled():
        return api_error("Frontend build is not enabled on this backend.", 404)

    safe_path = asset_path.strip("/") or "index.html"
    candidate = os.path.abspath(os.path.join(FRONTEND_BUILD_DIR, safe_path))
    frontend_root = os.path.abspath(FRONTEND_BUILD_DIR)

    try:
        is_frontend_asset = os.path.commonpath([frontend_root, candidate]) == frontend_root
    except ValueError:
        is_frontend_asset = False

    if is_frontend_asset and os.path.isfile(candidate):
        return send_from_directory(FRONTEND_BUILD_DIR, safe_path)

    return send_from_directory(FRONTEND_BUILD_DIR, "index.html")


def normalize_user_role(role):
    selected_role = str(role or "Viewer").strip()

    for allowed_role in USER_ROLES:
        if selected_role.lower() == allowed_role.lower():
            return allowed_role

    return "Viewer"


def access_level_for_role(role):
    return USER_ROLES[normalize_user_role(role)]["access_level"]


def user_is_admin(user):
    if not user:
        return False

    return str(user.role or "").lower() == "admin" or str(
        user.access_level or ""
    ).lower() == "administrator"


def user_can_operate(user):
    if not user:
        return False

    return user_is_admin(user) or normalize_user_role(user.role) == "SOC Analyst"


def serialize_user(user):
    if not user:
        return None

    return {
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "access_level": user.access_level,
        "is_active": user.is_active,
        "last_login": user.last_login.strftime("%Y-%m-%d %H:%M:%S")
        if user.last_login
        else None,
        "created_at": user.created_at.strftime("%Y-%m-%d %H:%M:%S")
        if user.created_at
        else None,
    }


def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    return db.session.get(User, user_id)


def login_required(view_func):
    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        user = current_user()
        if user is None:
            return api_error("Authentication required.", 401, authenticated=False)

        if not user.is_active:
            session.clear()
            return api_error("Account disabled.", 403, authenticated=False)

        return view_func(*args, **kwargs)

    return wrapped_view


def admin_required(view_func):
    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        user = current_user()
        if user is None:
            return api_error("Authentication required.", 401, authenticated=False)

        if not user.is_active:
            session.clear()
            return api_error("Account disabled.", 403, authenticated=False)

        if not user_is_admin(user):
            return api_error("Administrator access required.", 403)

        return view_func(*args, **kwargs)

    return wrapped_view


def ingest_api_key_valid():
    if not INGEST_API_KEY:
        return False

    supplied_key = (
        request.headers.get("X-EvoGuard-Ingest-Key")
        or request.headers.get("X-API-Key")
        or ""
    ).strip()
    auth_header = request.headers.get("Authorization", "")

    if auth_header.lower().startswith("bearer "):
        supplied_key = auth_header.split(" ", 1)[1].strip()

    return hmac.compare_digest(supplied_key, INGEST_API_KEY)


def ingest_auth_required(view_func):
    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        user = current_user()

        if user is not None:
            if not user.is_active:
                session.clear()
                return api_error("Account disabled.", 403, authenticated=False)

            if not user_can_operate(user):
                return api_error("Operator access required.", 403)

            return view_func(*args, **kwargs)

        if ingest_api_key_valid():
            request.environ["evoguard_ingest_actor"] = "ingest-api"
            return view_func(*args, **kwargs)

        return api_error(
            "Authentication required. Log in or send X-EvoGuard-Ingest-Key.",
            401,
            authenticated=False,
            ingest_key_required=bool(INGEST_API_KEY),
        )

    return wrapped_view


def build_event_uuid(event_source="event"):
    source = str(event_source or "event").upper()[:8]
    return f"{source}-{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}-{random.randint(1000, 9999)}"


def current_user_id():
    user = current_user()
    return user.id if user else None


def safe_json_dump(value):
    try:
        return json.dumps(value, default=str)
    except (TypeError, ValueError):
        return json.dumps({"raw": str(value)})


def log_audit_action(
    action,
    entity_type=None,
    entity_id=None,
    event_source=None,
    details=None,
    commit=True,
):
    if not has_request_context():
        return None

    user = current_user()
    ingest_actor = request.environ.get("evoguard_ingest_actor")
    audit_log = SystemAuditLog(
        actor_user_id=user.id if user else None,
        actor_username=user.username if user else ingest_actor or "anonymous",
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        event_source=event_source,
        ip_address=request.headers.get("X-Forwarded-For", request.remote_addr),
        user_agent=request.headers.get("User-Agent", "")[:255],
        details=safe_json_dump(details or {}),
    )
    db.session.add(audit_log)

    if commit:
        db.session.commit()

    broadcast_realtime_audit(audit_log)
    return audit_log


def log_report_generation(
    report_type,
    delivery_method,
    delivery_status,
    filename=None,
    recipient=None,
    summary=None,
    commit=True,
):
    report_log = ReportGenerationLog(
        report_type=report_type,
        delivery_method=delivery_method,
        delivery_status=delivery_status,
        filename=filename,
        recipient=recipient,
        generated_by_user_id=current_user_id() if has_request_context() else None,
        summary_json=safe_json_dump(summary or {}),
    )
    db.session.add(report_log)

    if commit:
        db.session.commit()

    broadcast_realtime_report(report_log)
    return report_log


def serialize_audit_log(log):
    return {
        "id": log.id,
        "actor_username": log.actor_username,
        "action": log.action,
        "entity_type": log.entity_type,
        "entity_id": log.entity_id,
        "event_source": log.event_source,
        "ip_address": log.ip_address,
        "timestamp": log.timestamp.strftime("%Y-%m-%d %H:%M:%S") if log.timestamp else None,
        "details": json.loads(log.details or "{}"),
    }


def serialize_report_log(log):
    return {
        "id": log.id,
        "report_type": log.report_type,
        "delivery_method": log.delivery_method,
        "delivery_status": log.delivery_status,
        "filename": log.filename,
        "recipient": log.recipient,
        "generated_at": log.generated_at.strftime("%Y-%m-%d %H:%M:%S")
        if log.generated_at
        else None,
        "summary": json.loads(log.summary_json or "{}"),
    }


def normalize_analysis(analysis):
    risk_score = int(analysis.get("risk_score", 0))
    risk_level = analysis.get("risk_level", "Low")
    actions = analysis.get("recommended_actions") or default_actions(risk_level)
    response_confidence = analysis.get("response_confidence")

    if response_confidence is None:
        response_confidence = min(99, max(50, risk_score))

    return {
        "attack_label": analysis.get("attack_label", "Unknown"),
        "attack_category": analysis.get("attack_category", "Unknown"),
        "risk_score": risk_score,
        "risk_level": risk_level,
        "explanation": analysis.get("explanation", "No explanation generated."),
        "recommended_actions": actions,
        "response_mode": analysis.get("response_mode", "Autonomous AI Response"),
        "response_confidence": float(response_confidence),
    }
def default_actions(risk_level):
    if risk_level == "Critical":
        return [
            "Isolate affected endpoint.",
            "Block malicious source IP address.",
            "Execute autonomous containment workflow.",
            "Preserve forensic evidence.",
        ]

    if risk_level == "High":
        return [
            "Block or rate-limit suspicious traffic.",
            "Analyze authentication and firewall logs.",
            "Add source to AI watchlist.",
            "Increase monitoring on targeted services.",
        ]

    return [
        "Continue passive monitoring.",
        "Store event as baseline telemetry.",
        "No autonomous containment required.",
    ]


def expected_action_count(risk_level):
    if risk_level == "Critical":
        return 4
    if risk_level == "High":
        return 3
    return 2


def risk_level_from_score(score):
    if score >= 85:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 30:
        return "Medium"
    return "Low"


def risk_alignment_score(risk_level, risk_score):
    if risk_score is None:
        return 60

    if risk_score >= 85:
        expected_level = "Critical"
    elif risk_score >= 60:
        expected_level = "High"
    elif risk_score >= 30:
        expected_level = "Medium"
    else:
        expected_level = "Low"

    if risk_level == expected_level:
        return 100

    if risk_level in ["Critical", "High"] and expected_level in ["Critical", "High"]:
        return 85

    return 65


def score_attack_response(log):
    analysis = normalize_analysis(agentic_analysis(log.attack_label))
    risk_score = int(log.risk_score or analysis["risk_score"] or 0)
    risk_level = log.risk_level or analysis["risk_level"]
    explanation = log.explanation or analysis["explanation"]
    actions = analysis["recommended_actions"] or default_actions(risk_level)

    if risk_level == "Low":
        detection_confidence = max(0, 100 - risk_score)
    else:
        detection_confidence = min(100, risk_score)

    explanation_score = 100 if explanation and len(explanation.strip()) >= 35 else 65
    action_score = min(100, (len(actions) / expected_action_count(risk_level)) * 100)

    mitigation_keywords = [
        "block",
        "isolate",
        "rate-limit",
        "monitor",
        "review",
        "preserve",
        "store",
        "continue",
    ]
    action_text = " ".join(actions).lower()
    mitigation_score = 100 if any(word in action_text for word in mitigation_keywords) else 60

    response_score = (action_score * 0.65) + (mitigation_score * 0.35)
    alignment_score = risk_alignment_score(risk_level, risk_score)

    return round(
        (detection_confidence * 0.35)
        + (response_score * 0.25)
        + (explanation_score * 0.20)
        + (alignment_score * 0.20),
        2,
    )


def calculate_ai_defense_score(logs):
    if not logs:
        return {
            "score": None,
            "score_display": "No Events",
            "evaluated_events": 0,
            "basis": [
                "No received attacks yet.",
                "Run a simulation or ingest events to calculate AI defense performance.",
            ],
        }

    evaluated_logs = logs[:50]
    event_scores = [score_attack_response(log) for log in evaluated_logs]
    score = round(sum(event_scores) / len(event_scores), 2)

    return {
        "score": score,
        "score_display": f"{score:.2f}%",
        "evaluated_events": len(evaluated_logs),
        "basis": [
            "Detection confidence from risk score.",
            "Risk-level alignment with severity.",
            "AI explanation completeness.",
            "Autonomous response action coverage.",
        ],
    }


def ai_response_blueprint(log, analysis):
    category = category_key_for_log(log)
    risk_level = log.risk_level or analysis["risk_level"]
    risk_score = int(log.risk_score or analysis["risk_score"] or 0)
    source_ip = log.source_ip or "Unknown"
    playbook = AI_RESPONSE_PLAYBOOK.get(category, AI_RESPONSE_PLAYBOOK["normal"])

    if risk_level == "Critical":
        stages = ["Detected", "Analyzed", "Mitigation Planned", "Action Executed", "Contained"]
        status = "Executed"
    elif risk_level == "High":
        stages = ["Detected", "Analyzed", "Mitigation Planned", "Action Executed", "Monitoring"]
        status = "Executed"
    elif risk_level == "Medium":
        stages = ["Detected", "Analyzed", "Mitigation Planned", "Monitoring"]
        status = "Monitoring"
    else:
        stages = ["Detected", "Analyzed", "Monitoring"]
        status = "Monitoring"

    base_confidence = float(analysis.get("response_confidence") or min(99, max(55, risk_score)))
    actions = playbook["actions"]

    return [
        {
            "action_name": action["action_name"],
            "action_type": action["action_type"],
            "execution_stage": stages[min(index, len(stages) - 1)],
            "status": status,
            "confidence": round(max(50, min(99, base_confidence - (index * 2.5))), 2),
            "explanation": (
                f"{playbook['name']}: {action['explanation']} "
                f"Impact: {action['impact']} Target source: {source_ip}."
            ),
        }
        for index, action in enumerate(actions)
    ]


def create_ai_response_logs(attack_log, analysis):
    response_logs = []

    for item in ai_response_blueprint(attack_log, analysis):
        response_log = AIResponseLog(
            attack_id=attack_log.id,
            action_name=item["action_name"],
            action_type=item["action_type"],
            execution_stage=item["execution_stage"],
            status=item["status"],
            confidence=item["confidence"],
            explanation=item["explanation"],
        )
        db.session.add(response_log)
        response_logs.append(response_log)

    db.session.commit()
    return response_logs


def category_key_from_text(attack_category="", attack_label=""):
    combined = f"{attack_category or ''} {attack_label or ''}".lower()

    if "normal" in combined:
        return "normal"
    if "dos" in combined or "ddos" in combined or "neptune" in combined:
        return "dos"
    if (
        "probe" in combined
        or "scan" in combined
        or "satan" in combined
        or "ipsweep" in combined
        or "portsweep" in combined
        or "nmap" in combined
    ):
        return "probe"
    if "r2l" in combined or "unauthorized" in combined or "credential" in combined:
        return "r2l"
    if "u2r" in combined or "privilege" in combined or "root" in combined:
        return "u2r"

    return "normal"


def mitre_for_category(category_key):
    return MITRE_ATTACK_MAPPING.get(category_key, MITRE_ATTACK_MAPPING["normal"])


def serialize_ioc(ioc):
    return {
        "id": ioc.id,
        "indicator_type": ioc.indicator_type,
        "indicator_value": ioc.indicator_value,
        "reputation": ioc.reputation,
        "confidence": ioc.confidence,
        "attack_category": ioc.attack_category,
        "source_name": ioc.source_name,
        "notes": ioc.notes,
        "sightings": ioc.sightings or 0,
        "first_seen": ioc.first_seen.strftime("%Y-%m-%d %H:%M:%S") if ioc.first_seen else None,
        "last_seen": ioc.last_seen.strftime("%Y-%m-%d %H:%M:%S") if ioc.last_seen else None,
    }


def matching_iocs(source_context, category_key):
    source_ip = str(source_context.get("source_ip") or "").lower()
    source_country = str(source_context.get("source_country") or "").lower()
    matches = []

    for ioc in ThreatIntelIOC.query.all():
        indicator_type = (ioc.indicator_type or "").lower()
        indicator_value = str(ioc.indicator_value or "").lower()

        if indicator_type == "ip" and source_ip and indicator_value == source_ip:
            matches.append(ioc)
        elif indicator_type == "country" and source_country and indicator_value == source_country:
            matches.append(ioc)
        elif indicator_type == "attack_category" and indicator_value == category_key:
            matches.append(ioc)

    return matches


def build_threat_intel_enrichment(analysis, source_context):
    category_key = category_key_from_text(
        analysis.get("attack_category"),
        analysis.get("attack_label"),
    )
    mitre = mitre_for_category(category_key)
    matches = matching_iocs(source_context, category_key)
    source_ip = source_context.get("source_ip")

    previous_sightings = 0
    if source_ip and source_ip != "Unknown":
        previous_sightings = AttackLog.query.filter(AttackLog.source_ip == source_ip).count()

    risk_delta = 0
    for ioc in matches:
        weight = THREAT_REPUTATION_WEIGHTS.get(ioc.reputation, 2)
        confidence_factor = max(0.25, min(1, float(ioc.confidence or 70) / 100))
        risk_delta += round(weight * confidence_factor)
        ioc.sightings = (ioc.sightings or 0) + 1
        ioc.last_seen = datetime.utcnow()

    risk_delta += min(10, previous_sightings * 2)
    risk_delta = max(-12, min(24, risk_delta))

    base_score = int(analysis.get("risk_score") or 0)
    enriched_score = max(0, min(100, base_score + risk_delta))
    highest_match = max(
        matches,
        key=lambda item: THREAT_REPUTATION_WEIGHTS.get(item.reputation, 0),
        default=None,
    )
    reputation = highest_match.reputation if highest_match else "No IOC Match"
    confidence = max([float(item.confidence or 0) for item in matches] or [0])

    if matches:
        match_text = ", ".join(
            f"{item.indicator_type}:{item.indicator_value}" for item in matches[:3]
        )
        summary = (
            f"{len(matches)} IOC match(es) found ({match_text}). "
            f"MITRE mapping: {mitre['technique']}."
        )
    else:
        summary = f"No direct IOC match. MITRE mapping: {mitre['technique']}."

    if previous_sightings:
        summary += f" Previous sightings from this source: {previous_sightings}."

    intel_actions = []
    if matches:
        intel_actions.append(f"Apply threat-intel policy for {reputation} source.")
        intel_actions.append(f"Map event to {mitre['technique']} for response tracking.")
    if previous_sightings:
        intel_actions.append("Increase priority because the source has previous sightings.")

    enriched_analysis = {
        **analysis,
        "risk_score": enriched_score,
        "risk_level": risk_level_from_score(enriched_score),
        "explanation": f"{analysis.get('explanation')} Threat intelligence: {summary}",
        "recommended_actions": list(dict.fromkeys(intel_actions + analysis["recommended_actions"])),
    }

    intel = {
        "reputation": reputation,
        "confidence": confidence,
        "score": enriched_score,
        "risk_delta": risk_delta,
        "summary": summary,
        "mitre_technique": mitre["technique"],
        "mitre_tactic": mitre["tactic"],
        "mitre_priority": mitre["priority"],
        "previous_sightings": previous_sightings,
        "ioc_matches": [serialize_ioc(item) for item in matches],
    }

    db.session.flush()
    return enriched_analysis, intel


def apply_intel_to_log(log, intel):
    log.intel_reputation = intel["reputation"]
    log.intel_confidence = intel["confidence"]
    log.intel_score = intel["score"]
    log.intel_summary = intel["summary"]
    log.mitre_technique = intel["mitre_technique"]
    log.mitre_tactic = intel["mitre_tactic"]
    log.ioc_matches = json.dumps(intel["ioc_matches"])


def response_decision_for_status(status):
    if status == "Executed":
        return "Autonomous action executed"
    if status == "Monitoring":
        return "Autonomous monitoring active"
    return "Action pending"


def response_outcome_for_status(status):
    if status == "Executed":
        return "Simulated defense control completed successfully."
    if status == "Monitoring":
        return "AI is monitoring the condition before further disruption."
    return "Awaiting additional telemetry."


def serialize_ai_response_log(response_log):
    attack = db.session.get(AttackLog, response_log.attack_id)
    category = category_key_for_log(attack) if attack else "normal"
    playbook = AI_RESPONSE_PLAYBOOK.get(category, AI_RESPONSE_PLAYBOOK["normal"])

    return {
        "id": response_log.id,
        "attack_id": response_log.attack_id,
        "attack_category": attack.attack_category if attack else None,
        "attack_label": attack.attack_label if attack else None,
        "risk_level": attack.risk_level if attack else None,
        "risk_score": attack.risk_score if attack else None,
        "event_source": attack.event_source if attack else None,
        "source_country": attack.source_country if attack else None,
        "source_ip": attack.source_ip if attack else None,
        "playbook_name": playbook["name"],
        "automation_level": playbook["automation_level"],
        "response_decision": response_decision_for_status(response_log.status),
        "response_outcome": response_outcome_for_status(response_log.status),
        "action_name": response_log.action_name,
        "action_type": response_log.action_type,
        "execution_stage": response_log.execution_stage,
        "status": response_log.status,
        "confidence": response_log.confidence,
        "explanation": response_log.explanation,
        "timestamp": response_log.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
    }


def response_summary_for_logs(logs):
    if not logs:
        return {
            "total_actions": 0,
            "executed_actions": 0,
            "monitoring_actions": 0,
            "pending_actions": 0,
            "execution_rate": 0,
            "automation_mode": "No Events",
            "containment_status": "No Events",
            "average_confidence": None,
        }

    attack_ids = [log.id for log in logs]
    response_logs = AIResponseLog.query.filter(AIResponseLog.attack_id.in_(attack_ids)).all()

    if not response_logs:
        return {
            "total_actions": 0,
            "executed_actions": 0,
            "monitoring_actions": 0,
            "pending_actions": 0,
            "execution_rate": 0,
            "automation_mode": "Pending",
            "containment_status": "Pending",
            "average_confidence": None,
        }

    executed_actions = sum(1 for item in response_logs if item.status == "Executed")
    monitoring_actions = sum(1 for item in response_logs if item.status == "Monitoring")
    pending_actions = len(response_logs) - executed_actions - monitoring_actions
    execution_rate = round((executed_actions / len(response_logs)) * 100, 2)
    average_confidence = round(
        sum(item.confidence or 0 for item in response_logs) / len(response_logs),
        2,
    )

    return {
        "total_actions": len(response_logs),
        "executed_actions": executed_actions,
        "monitoring_actions": monitoring_actions,
        "pending_actions": pending_actions,
        "execution_rate": execution_rate,
        "automation_mode": "Autonomous AI",
        "containment_status": "Contained" if executed_actions else "Monitoring",
        "average_confidence": average_confidence,
    }


def dashboard_stats_payload(source="all"):
    query = filter_logs_by_source(
        AttackLog.query.order_by(AttackLog.timestamp.desc()),
        source,
    )
    logs = query.all()

    total_threats = len(logs)
    critical_alerts = sum(1 for log in logs if log.risk_level == "Critical")
    high_risk = sum(1 for log in logs if log.risk_level == "High")
    low_risk = sum(1 for log in logs if log.risk_level == "Low")

    category_counts = {
        "dos": 0,
        "probe": 0,
        "r2l": 0,
        "u2r": 0,
        "normal": 0,
    }

    for log in logs:
        category_counts[category_key_for_log(log)] += 1

    today = datetime.utcnow().date()
    trend_days = [today - timedelta(days=offset) for offset in range(4, -1, -1)]
    weekly_trend = [
        {
            "day": day.strftime("%a"),
            "attacks": sum(
                1
                for log in logs
                if log.timestamp and log.timestamp.date() == day
            ),
        }
        for day in trend_days
    ]

    latest_attack = serialize_attack_log(logs[0]) if logs else None
    model_metrics = load_model_metrics()
    ai_defense_metrics = calculate_ai_defense_score(logs)
    ai_response_summary = response_summary_for_logs(logs)
    threat_intel_summary = threat_intel_summary_for_logs(logs)

    return {
        "source": source,
        "total_threats": total_threats,
        "critical_alerts": critical_alerts,
        "high_risk": high_risk,
        "normal_events": low_risk,
        "category_counts": category_counts,
        "weekly_trend": weekly_trend,
        "latest_attack": latest_attack,
        "model_accuracy": ai_defense_metrics["score_display"],
        "ai_defense_score": ai_defense_metrics,
        "ai_response_summary": ai_response_summary,
        "threat_intel_summary": threat_intel_summary,
        "model_metrics": model_metrics,
        "features_used": len(AI["selected_features"]),
    }


def safe_json_list(raw_value):
    if not raw_value:
        return []

    try:
        parsed = json.loads(raw_value)
    except (TypeError, ValueError):
        return []

    return parsed if isinstance(parsed, list) else []


def threat_intel_summary_for_logs(logs):
    enriched_logs = [log for log in logs if log.intel_reputation]
    ioc_matches = []
    mitre_counts = {}
    reputation_counts = {}
    repeated_sources = 0

    for log in enriched_logs:
        reputation = log.intel_reputation or "Unknown"
        reputation_counts[reputation] = reputation_counts.get(reputation, 0) + 1

        if log.mitre_technique:
            mitre_counts[log.mitre_technique] = mitre_counts.get(log.mitre_technique, 0) + 1

        matches = safe_json_list(log.ioc_matches)
        ioc_matches.extend(matches)
        if len(matches) > 0 or (log.intel_summary and "Previous sightings" in log.intel_summary):
            repeated_sources += 1

    return {
        "enriched_events": len(enriched_logs),
        "ioc_matches": len(ioc_matches),
        "malicious_events": sum(
            count
            for reputation, count in reputation_counts.items()
            if reputation in ["Malicious", "Critical", "High Risk"]
        ),
        "watchlist_events": sum(
            count
            for reputation, count in reputation_counts.items()
            if reputation in ["Suspicious", "Watchlist", "High Impact"]
        ),
        "reputation_counts": reputation_counts,
        "mitre_counts": mitre_counts,
        "repeat_source_events": repeated_sources,
    }


def realtime_enabled():
    return socketio is not None


def realtime_status_payload(source="live"):
    selected_source = source if source in ["all", "live", "simulation"] else "live"
    return {
        "enabled": realtime_enabled(),
        "source": selected_source,
        "transport": "socket.io" if realtime_enabled() else "polling",
        "connected_clients": len(ACTIVE_SOCKET_CLIENTS),
        "server_time": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "events": [
            "evoguard:connected",
            "evoguard:heartbeat",
            "evoguard:new_attack",
            "evoguard:ai_response",
            "evoguard:stats_updated",
            "evoguard:threat_intel_updated",
            "evoguard:audit_event",
            "evoguard:report_event",
            "evoguard:history_reset",
        ],
    }


def broadcast_realtime_update(attack_log):
    if not realtime_enabled():
        return

    source = attack_log.event_source or "simulation"
    serialized_attack = serialize_attack_log(attack_log)
    response_logs = (
        AIResponseLog.query.filter_by(attack_id=attack_log.id)
        .order_by(AIResponseLog.timestamp.asc(), AIResponseLog.id.asc())
        .all()
    )
    serialized_responses = [serialize_ai_response_log(item) for item in response_logs]
    stats = dashboard_stats_payload(source)
    threat_intel = threat_intel_payload(source)
    summary = response_summary_for_logs(
        filter_logs_by_source(
            AttackLog.query.order_by(AttackLog.timestamp.desc()),
            source,
        ).all()
    )

    socketio.emit(
        "evoguard:new_attack",
        {
            "source": source,
            "attack": serialized_attack,
            "stats": stats,
            "threat_intel": threat_intel,
            "server_time": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        },
    )
    socketio.emit(
        "evoguard:ai_response",
        {
            "source": source,
            "attack_id": attack_log.id,
            "responses": serialized_responses,
            "summary": summary,
            "server_time": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        },
    )
    socketio.emit("evoguard:stats_updated", stats)
    socketio.emit(
        "evoguard:threat_intel_updated",
        {
            "source": source,
            "threat_intel": threat_intel,
            "server_time": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        },
    )


def broadcast_realtime_audit(audit_log):
    if realtime_enabled() and audit_log:
        socketio.emit("evoguard:audit_event", serialize_audit_log(audit_log))


def broadcast_realtime_report(report_log):
    if realtime_enabled() and report_log:
        socketio.emit("evoguard:report_event", serialize_report_log(report_log))


def broadcast_history_reset(source, deleted_records):
    if not realtime_enabled():
        return

    selected_source = source if source in ["all", "live", "simulation"] else "all"
    socketio.emit(
        "evoguard:history_reset",
        {
            "source": selected_source,
            "deleted_records": deleted_records,
            "stats": dashboard_stats_payload(selected_source),
            "server_time": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        },
    )


def socket_sync_payload(source="live"):
    selected_source = source if source in ["all", "live", "simulation"] else "live"
    logs = (
        filter_logs_by_source(
            AttackLog.query.order_by(AttackLog.timestamp.desc(), AttackLog.id.desc()),
            selected_source,
        )
        .limit(50)
        .all()
    )

    response_query = AIResponseLog.query.join(
        AttackLog,
        AIResponseLog.attack_id == AttackLog.id,
    )

    if selected_source in ["live", "simulation"]:
        response_query = response_query.filter(AttackLog.event_source == selected_source)

    responses = (
        response_query.order_by(
            AIResponseLog.timestamp.desc(),
            AIResponseLog.id.desc(),
        )
        .limit(24)
        .all()
    )

    return {
        "source": selected_source,
        "status": "connected",
        "stats": dashboard_stats_payload(selected_source),
        "history": [serialize_attack_log(log) for log in logs],
        "responses": [serialize_ai_response_log(item) for item in responses],
        "threat_intel": threat_intel_payload(selected_source),
        "realtime_status": realtime_status_payload(selected_source),
        "realtime": realtime_enabled(),
        "server_time": datetime.utcnow().isoformat(timespec="seconds") + "Z",
    }


def register_socket_handlers():
    global socket_handlers_registered

    if not socketio or socket_handlers_registered:
        return

    socket_handlers_registered = True

    @socketio.on("connect")
    def handle_socket_connect():
        ACTIVE_SOCKET_CLIENTS.add(request.sid)
        emit("evoguard:connected", socket_sync_payload("live"))

    @socketio.on("disconnect")
    def handle_socket_disconnect():
        ACTIVE_SOCKET_CLIENTS.discard(request.sid)

    @socketio.on("evoguard:request_sync")
    def handle_socket_sync(payload=None):
        requested = (payload or {}).get("source", "live")
        emit("evoguard:connected", socket_sync_payload(requested))

    @socketio.on("evoguard:ping")
    def handle_socket_ping(payload=None):
        requested = (payload or {}).get("source", "live")
        emit("evoguard:heartbeat", realtime_status_payload(requested))


def get_source_context():
    sources = [
        ("Russia", "DDoS traffic"),
        ("China", "Probe scans"),
        ("USA", "R2L attempts"),
        ("Iran", "U2R attempts"),
        ("Germany", "Credential activity"),
        ("Brazil", "Botnet traffic"),
        ("India", "Reconnaissance activity"),
        ("North Korea", "Intrusion attempt"),
    ]

    country, activity = random.choice(sources)
    ip = ".".join(str(random.randint(1, 254)) for _ in range(4))

    return {
        "source_country": country,
        "source_ip": ip,
        "source_activity": activity,
    }



def normalize_live_attack_label(raw_label):
    label = str(raw_label or "").strip()
    if not label:
        return "neptune"

    lowered = label.lower()

    if lowered in LIVE_EVENT_ALIASES:
        return LIVE_EVENT_ALIASES[lowered]

    for keyword, mapped_label in LIVE_EVENT_ALIASES.items():
        if keyword in lowered:
            return mapped_label

    return lowered.replace(" ", "_")


def live_event_payload_summary(payload, normalized_label):
    parts = [
        payload.get("source_activity"),
        payload.get("activity"),
        payload.get("description"),
        payload.get("raw_event"),
    ]
    summary = next((str(part).strip() for part in parts if part), "")

    if summary:
        return summary[:120]

    return f"Live event normalized as {normalized_label}"


def random_public_test_ip():
    return random.choice(["192.0.2", "198.51.100", "203.0.113"]) + f".{random.randint(10, 240)}"


def clean_text(value, default="", max_length=120):
    text_value = str(value or default).strip()
    return text_value[:max_length]


def normalize_ip_value(value):
    ip_value = clean_text(value, "", 64)

    if not ip_value or ip_value.lower() in {"unknown", "external"}:
        return "Unknown"

    try:
        return str(ipaddress.ip_address(ip_value))
    except ValueError as error:
        raise ValueError(f"Invalid source IP address: {ip_value}") from error


def normalize_protocol(value):
    protocol = clean_text(value, "tcp", 20).lower()
    return protocol if protocol in {"tcp", "udp", "icmp", "http", "https", "dns"} else "tcp"


def normalize_destination_port(value):
    if value in [None, ""]:
        return None

    try:
        port = int(value)
    except (TypeError, ValueError) as error:
        raise ValueError("destination_port must be a number between 0 and 65535.") from error

    if port < 0 or port > 65535:
        raise ValueError("destination_port must be between 0 and 65535.")

    return port


def validate_live_event_payload(payload):
    event = payload or {}
    raw_label = (
        event.get("attack_label")
        or event.get("label")
        or event.get("attack_type")
        or event.get("category")
        or "ddos"
    )
    source_activity = live_event_payload_summary(event, normalize_live_attack_label(raw_label))

    return {
        **event,
        "attack_label": clean_text(raw_label, "ddos", 100),
        "attack_type": clean_text(event.get("attack_type") or raw_label, "dos", 40).lower(),
        "country": clean_text(event.get("country") or event.get("source_country"), "External", 100),
        "ip": normalize_ip_value(event.get("ip") or event.get("source_ip") or "Unknown"),
        "source_activity": clean_text(source_activity, "Live event received by EvoGuard", 120),
        "sensor_name": clean_text(event.get("sensor_name") or event.get("sensor"), "Manual Live Intake", 120),
        "target_asset": clean_text(event.get("target_asset") or event.get("asset"), "UAE Protected Network", 140),
        "network_protocol": normalize_protocol(event.get("network_protocol") or event.get("protocol")),
        "destination_port": normalize_destination_port(
            event.get("destination_port") or event.get("dst_port") or event.get("port")
        ),
    }


def build_live_test_payload(event_type="random"):
    if event_type == "random":
        event_type = random.choice(list(LIVE_TEST_EVENT_LIBRARY.keys()))

    if event_type not in LIVE_TEST_EVENT_LIBRARY:
        raise ValueError(f"Unsupported live test event type: {event_type}")

    payload = random.choice(LIVE_TEST_EVENT_LIBRARY[event_type]).copy()
    payload["attack_type"] = event_type
    payload["ip"] = random_public_test_ip()
    payload["sensor_name"] = "EvoGuard Live Intake"
    payload["target_asset"] = "UAE Protected Network"
    payload["network_protocol"] = "tcp"
    payload["destination_port"] = 443 if event_type in ["dos", "probe"] else 22
    return payload


def normalize_bulk_event(raw_event):
    event = raw_event or {}
    return validate_live_event_payload({
        "attack_type": event.get("attack_type")
        or event.get("type")
        or event.get("attack")
        or event.get("attack_label")
        or "dos",
        "attack_label": event.get("attack_label") or event.get("label"),
        "country": event.get("country") or event.get("source_country") or "External",
        "ip": event.get("ip") or event.get("source_ip") or random_public_test_ip(),
        "source_activity": event.get("source_activity")
        or event.get("activity")
        or event.get("description")
        or "Bulk live event imported into EvoGuard",
        "sensor_name": event.get("sensor_name") or event.get("sensor"),
        "target_asset": event.get("target_asset") or event.get("asset"),
        "network_protocol": event.get("network_protocol") or event.get("protocol"),
        "destination_port": event.get("destination_port") or event.get("dst_port") or event.get("port"),
    })


def parse_csv_events(csv_text):
    reader = csv.DictReader(io.StringIO(csv_text))
    return [normalize_bulk_event(row) for row in reader]


def create_live_attack_log(payload):
    payload = validate_live_event_payload(payload)
    raw_attack_label = (
        payload.get("attack_label")
        or payload.get("label")
        or payload.get("attack_type")
        or payload.get("category")
        or "ddos"
    )
    normalized_label = normalize_live_attack_label(raw_attack_label)
    source_context = {
        "source_country": payload.get("country") or payload.get("source_country") or "External",
        "source_ip": payload.get("ip") or payload.get("source_ip") or "Unknown",
        "source_activity": live_event_payload_summary(payload, normalized_label),
    }
    analysis = normalize_analysis(agentic_analysis(normalized_label))
    analysis, threat_intel = build_threat_intel_enrichment(analysis, source_context)
    attack_type = category_key_from_text(analysis["attack_category"], analysis["attack_label"])

    new_log = AttackLog(
        event_uuid=build_event_uuid("live"),
        attack_label=analysis["attack_label"],
        attack_category=analysis["attack_category"],
        attack_type=attack_type,
        risk_score=analysis["risk_score"],
        risk_level=analysis["risk_level"],
        explanation=analysis["explanation"],
        event_source="live",
        event_status="autonomous_response_generated",
        source_country=source_context["source_country"],
        source_ip=source_context["source_ip"],
        source_activity=source_context["source_activity"],
        raw_payload=safe_json_dump(payload),
        sensor_name=payload["sensor_name"],
        target_asset=payload["target_asset"],
        network_protocol=payload["network_protocol"],
        destination_port=payload["destination_port"],
        response_mode=analysis["response_mode"],
        response_confidence=analysis["response_confidence"],
        created_by_user_id=current_user_id() if has_request_context() else None,
    )
    apply_intel_to_log(new_log, threat_intel)

    db.session.add(new_log)
    db.session.commit()
    create_ai_response_logs(new_log, analysis)
    log_audit_action(
        "live_event_ingested",
        entity_type="attack_log",
        entity_id=new_log.id,
        event_source="live",
        details={
            "attack_type": attack_type,
            "risk_level": new_log.risk_level,
            "source_ip": new_log.source_ip,
            "source_country": new_log.source_country,
            "sensor_name": new_log.sensor_name,
            "target_asset": new_log.target_asset,
        },
    )
    broadcast_realtime_update(new_log)

    return {
        **serialize_attack_log(new_log),
        "status": "received",
        "raw_attack_label": raw_attack_label,
        "normalized_attack_label": normalized_label,
        "mitigation_status": "Autonomous AI response generated",
        "threat_intel": threat_intel,
    }


def predict_and_log(sample_data, attack_type="unknown"):
    if sample_data is None:
        raise ValueError("No sample data provided.")

    df = pd.DataFrame(sample_data)
    label_encoders = AI["label_encoders"]
    selected_features = AI["selected_features"]
    model = AI["model"]

    for col in ["protocol_type", "service"]:
        if col not in df.columns:
            raise ValueError(f"Missing required feature: {col}")

        if col not in label_encoders:
            raise ValueError(f"Missing label encoder for feature: {col}")

        value = df[col].iloc[0]
        encoder = label_encoders[col]

        if value not in encoder.classes_:
            raise ValueError(f"Unsupported value '{value}' for feature '{col}'")

        df[col] = encoder.transform(df[col])

    missing_features = [feature for feature in selected_features if feature not in df]

    if missing_features:
        raise ValueError(f"Sample data is missing features: {missing_features}")

    prediction = model.predict(df[selected_features])
    attack_label = label_encoders["label"].inverse_transform(prediction)[0]

    source_context = get_source_context()
    analysis = normalize_analysis(agentic_analysis(attack_label))
    analysis, threat_intel = build_threat_intel_enrichment(analysis, source_context)
    normalized_attack_type = (
        attack_type if attack_type in AVAILABLE_ATTACK_TYPES else category_key_from_text(
            analysis["attack_category"],
            analysis["attack_label"],
        )
    )

    new_log = AttackLog(
        event_uuid=build_event_uuid("simulation"),
        attack_label=analysis["attack_label"],
        attack_category=analysis["attack_category"],
        attack_type=normalized_attack_type,
        risk_score=analysis["risk_score"],
        risk_level=analysis["risk_level"],
        explanation=analysis["explanation"],
        event_source="simulation",
        event_status="autonomous_response_generated",
        source_country=source_context["source_country"],
        source_ip=source_context["source_ip"],
        source_activity=source_context["source_activity"],
        raw_payload=safe_json_dump(
            {
                "attack_type": attack_type,
                "sample_data": sample_data,
                "source_context": source_context,
            }
        ),
        response_mode=analysis["response_mode"],
        response_confidence=analysis["response_confidence"],
        created_by_user_id=current_user_id() if has_request_context() else None,
    )
    apply_intel_to_log(new_log, threat_intel)

    db.session.add(new_log)
    db.session.commit()
    create_ai_response_logs(new_log, analysis)
    log_audit_action(
        "simulation_event_generated",
        entity_type="attack_log",
        entity_id=new_log.id,
        event_source="simulation",
        details={
            "attack_type": normalized_attack_type,
            "risk_level": new_log.risk_level,
            "source_ip": new_log.source_ip,
            "source_country": new_log.source_country,
        },
    )
    broadcast_realtime_update(new_log)

    return {
        **analysis,
        **source_context,
        "id": new_log.id,
        "event_uuid": new_log.event_uuid,
        "event_source": "simulation",
        "attack_type": normalized_attack_type,
        "timestamp": new_log.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "mitigation_status": "Generated",
        "threat_intel": threat_intel,
    }


def get_sample_data(attack_type):
    samples = {
        "dos": {
            "protocol_type": ["tcp"],
            "service": ["private"],
            "src_bytes": [0],
            "dst_bytes": [0],
            "wrong_fragment": [0],
            "urgent": [0],
            "hot": [0],
            "root_shell": [0],
            "num_root": [0],
            "num_access_files": [0],
            "is_host_login": [0],
            "srv_count": [300],
            "serror_rate": [1.0],
            "rerror_rate": [0.0],
            "diff_srv_rate": [0.06],
            "srv_diff_host_rate": [0.0],
            "dst_host_count": [255],
            "dst_host_diff_srv_rate": [0.06],
            "dst_host_srv_diff_host_rate": [0.0],
            "dst_host_rerror_rate": [0.0],
        },
        "probe": {
            "protocol_type": ["tcp"],
            "service": ["private"],
            "src_bytes": [0],
            "dst_bytes": [0],
            "wrong_fragment": [0],
            "urgent": [0],
            "hot": [0],
            "root_shell": [0],
            "num_root": [0],
            "num_access_files": [0],
            "is_host_login": [0],
            "srv_count": [1],
            "serror_rate": [0.0],
            "rerror_rate": [1.0],
            "diff_srv_rate": [0.07],
            "srv_diff_host_rate": [0.0],
            "dst_host_count": [255],
            "dst_host_diff_srv_rate": [0.07],
            "dst_host_srv_diff_host_rate": [0.0],
            "dst_host_rerror_rate": [1.0],
        },
        "r2l": {
            "protocol_type": ["tcp"],
            "service": ["ftp"],
            "src_bytes": [100],
            "dst_bytes": [200],
            "wrong_fragment": [0],
            "urgent": [0],
            "hot": [0],
            "root_shell": [0],
            "num_root": [0],
            "num_access_files": [0],
            "is_host_login": [0],
            "srv_count": [20],
            "serror_rate": [0.0],
            "rerror_rate": [0.0],
            "diff_srv_rate": [0.0],
            "srv_diff_host_rate": [0.0],
            "dst_host_count": [100],
            "dst_host_diff_srv_rate": [0.1],
            "dst_host_srv_diff_host_rate": [0.0],
            "dst_host_rerror_rate": [0.0],
        },
        "u2r": {
            "protocol_type": ["tcp"],
            "service": ["telnet"],
            "src_bytes": [500],
            "dst_bytes": [1000],
            "wrong_fragment": [0],
            "urgent": [0],
            "hot": [5],
            "root_shell": [1],
            "num_root": [5],
            "num_access_files": [2],
            "is_host_login": [0],
            "srv_count": [5],
            "serror_rate": [0.0],
            "rerror_rate": [0.0],
            "diff_srv_rate": [0.0],
            "srv_diff_host_rate": [0.0],
            "dst_host_count": [50],
            "dst_host_diff_srv_rate": [0.1],
            "dst_host_srv_diff_host_rate": [0.0],
            "dst_host_rerror_rate": [0.0],
        },
        "normal": {
            "protocol_type": ["tcp"],
            "service": ["http"],
            "src_bytes": [181],
            "dst_bytes": [5450],
            "wrong_fragment": [0],
            "urgent": [0],
            "hot": [0],
            "root_shell": [0],
            "num_root": [0],
            "num_access_files": [0],
            "is_host_login": [0],
            "srv_count": [9],
            "serror_rate": [0.0],
            "rerror_rate": [0.0],
            "diff_srv_rate": [0.0],
            "srv_diff_host_rate": [0.0],
            "dst_host_count": [9],
            "dst_host_diff_srv_rate": [0.0],
            "dst_host_srv_diff_host_rate": [0.0],
            "dst_host_rerror_rate": [0.0],
        },
    }

    return samples.get(attack_type)


def draw_wrapped_text(c, text_value, x, y, max_chars=95, line_height=14, font="Helvetica", size=9):
    text_value = str(text_value or "")
    words = text_value.split()
    line = ""
    c.setFont(font, size)

    for word in words:
        candidate = f"{line} {word}".strip()
        if len(candidate) > max_chars and line:
            c.drawString(x, y, line)
            y -= line_height
            line = word
        else:
            line = candidate

    if line:
        c.drawString(x, y, line)
        y -= line_height

    return y


def create_pdf_report(report_type="Incident"):
    report_type = normalize_report_type(report_type)
    os.makedirs(REPORT_DIR, exist_ok=True)

    filename = f"evoguard_{report_type.lower()}_report.pdf"
    report_path = os.path.join(REPORT_DIR, filename)
    latest_logs = AttackLog.query.order_by(AttackLog.timestamp.desc()).limit(10).all()
    stats = dashboard_stats_payload("all")
    response_summary = stats["ai_response_summary"]
    threat_summary = stats["threat_intel_summary"]

    c = canvas.Canvas(report_path, pagesize=A4)
    width, height = A4

    c.setFont("Helvetica-Bold", 18)
    c.drawString(50, height - 50, f"EvoGuard {report_type} Security Report")

    c.setFont("Helvetica", 11)
    c.drawString(
        50,
        height - 80,
        f"Generated At: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
    )
    c.drawString(50, height - 105, "System: EvoGuard Enterprise")
    c.drawString(50, height - 130, "Mode: AI Detection + Agentic Analysis")

    c.setFont("Helvetica-Bold", 13)
    c.drawString(50, height - 170, "Threat Summary")

    c.setFont("Helvetica", 11)
    c.drawString(70, height - 195, f"Total Threats Detected: {stats['total_threats']}")
    c.drawString(70, height - 220, f"Critical Alerts: {stats['critical_alerts']}")
    c.drawString(70, height - 245, f"High Risk Events: {stats['high_risk']}")
    c.drawString(70, height - 270, f"AI Defense Score: {stats['model_accuracy']}")
    c.drawString(70, height - 295, f"Optimized Features Used: {stats['features_used']}")

    c.setFont("Helvetica-Bold", 13)
    c.drawString(50, height - 330, "AI Response + Threat Intel")

    c.setFont("Helvetica", 10)
    c.drawString(70, height - 355, f"AI Actions Generated: {response_summary['total_actions']}")
    c.drawString(70, height - 378, f"Executed Actions: {response_summary['executed_actions']}")
    c.drawString(70, height - 401, f"Containment Status: {response_summary['containment_status']}")
    c.drawString(70, height - 424, f"IOC Matches: {threat_summary['ioc_matches']}")
    c.drawString(70, height - 447, f"Enriched Events: {threat_summary['enriched_events']}")

    c.setFont("Helvetica-Bold", 13)
    c.drawString(50, height - 485, "Recent Incidents")

    y = height - 510
    c.setFont("Helvetica", 9)

    if latest_logs:
        for log in latest_logs:
            serialized = serialize_attack_log(log)
            if y < 95:
                c.showPage()
                y = height - 60
                c.setFont("Helvetica", 9)

            line = (
                f"{serialized['timestamp']} | {serialized['attack_category']} | "
                f"{serialized['risk_level']} | {serialized['risk_score']}/100 | "
                f"{serialized['country']} | {serialized['threat_intel']['reputation']}"
            )
            y = draw_wrapped_text(c, line, 70, y, max_chars=92, line_height=12)
            mitre_line = f"MITRE: {serialized['threat_intel']['mitre_technique']}"
            y = draw_wrapped_text(c, mitre_line, 90, y, max_chars=88, line_height=12)
            y -= 4
    else:
        c.drawString(70, y, "No incidents recorded yet.")
        y -= 18

    y -= 18
    if y < 125:
        c.showPage()
        y = height - 60

    c.setFont("Helvetica-Bold", 13)
    c.drawString(50, y, "Recommended Actions")
    y -= 25

    c.setFont("Helvetica", 11)

    for action in [
        "Review IOC-matched sources and repeated attacker IPs.",
        "Prioritize Critical and High events with executed containment actions.",
        "Use MITRE mappings to explain AI response decisions.",
        "Export enriched incidents for final SOC evidence.",
    ]:
        y = draw_wrapped_text(c, f"- {action}", 70, y, max_chars=85, line_height=16, size=10)

    c.save()

    return report_path


def send_email_report(receiver_email, report_type="Weekly"):
    report_type = normalize_report_type(report_type)
    sender_email = os.getenv("EVOGUARD_EMAIL")
    app_password = os.getenv("EVOGUARD_EMAIL_PASSWORD")

    if not receiver_email or "@" not in receiver_email:
        raise ValueError("A valid analyst email address is required.")

    if not sender_email or not app_password:
        raise RuntimeError(
            "Email credentials are missing. Set EVOGUARD_EMAIL and EVOGUARD_EMAIL_PASSWORD."
        )

    report_path = create_pdf_report(report_type)

    msg = EmailMessage()
    msg["Subject"] = f"EvoGuard {report_type} Cybersecurity Report"
    msg["From"] = sender_email
    msg["To"] = receiver_email

    msg.set_content(
        f"""Dear EvoGuard Operator,

Please find attached the EvoGuard {report_type} cybersecurity report.

Regards,
EvoGuard Agentic AI Cyber Defense System
"""
    )

    with open(report_path, "rb") as file:
        msg.add_attachment(
            file.read(),
            maintype="application",
            subtype="pdf",
            filename=os.path.basename(report_path),
        )

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
        smtp.login(sender_email, app_password)
        smtp.send_message(msg)

    return report_path


def report_email_response(report_type):
    try:
        report_path = send_email_report(DEFAULT_ANALYST_EMAIL, report_type)
    except RuntimeError as error:
        log_report_generation(
            report_type,
            "email",
            "not_sent",
            recipient=DEFAULT_ANALYST_EMAIL,
            summary={"error": str(error)},
        )
        return api_error(
            str(error),
            503,
            setup_required=True,
            delivery="not_sent",
            report_type=report_type,
        )

    log_report_generation(
        report_type,
        "email",
        "sent",
        filename=os.path.basename(report_path),
        recipient=DEFAULT_ANALYST_EMAIL,
        summary=dashboard_stats_payload("all"),
    )
    log_audit_action(
        "report_emailed",
        entity_type="report_generation_log",
        details={
            "report_type": report_type,
            "receiver": DEFAULT_ANALYST_EMAIL,
            "filename": os.path.basename(report_path),
        },
    )

    return jsonify(
        {
            "status": "sent",
            "message": f"{report_type} report sent successfully.",
            "report_type": report_type,
            "receiver": DEFAULT_ANALYST_EMAIL,
            "filename": os.path.basename(report_path),
        }
    )


def parse_reset_confirmation():
    payload = request.get_json(silent=True) or {}
    return (
        request.args.get("confirm")
        or payload.get("confirm")
        or request.form.get("confirm")
        or ""
    )



def ensure_attacklog_schema():
    if not db.engine.url.drivername.startswith("sqlite"):
        return

    columns = {
        row[1]
        for row in db.session.execute(text("PRAGMA table_info(attack_log)")).fetchall()
    }

    migrations = {
        "event_uuid": "ALTER TABLE attack_log ADD COLUMN event_uuid VARCHAR(80)",
        "event_source": "ALTER TABLE attack_log ADD COLUMN event_source VARCHAR(50) DEFAULT 'simulation'",
        "attack_type": "ALTER TABLE attack_log ADD COLUMN attack_type VARCHAR(40)",
        "event_status": "ALTER TABLE attack_log ADD COLUMN event_status VARCHAR(60) DEFAULT 'analyzed'",
        "source_country": "ALTER TABLE attack_log ADD COLUMN source_country VARCHAR(100)",
        "source_ip": "ALTER TABLE attack_log ADD COLUMN source_ip VARCHAR(64)",
        "source_activity": "ALTER TABLE attack_log ADD COLUMN source_activity VARCHAR(120)",
        "raw_payload": "ALTER TABLE attack_log ADD COLUMN raw_payload TEXT",
        "sensor_name": "ALTER TABLE attack_log ADD COLUMN sensor_name VARCHAR(120)",
        "target_asset": "ALTER TABLE attack_log ADD COLUMN target_asset VARCHAR(140)",
        "network_protocol": "ALTER TABLE attack_log ADD COLUMN network_protocol VARCHAR(20)",
        "destination_port": "ALTER TABLE attack_log ADD COLUMN destination_port INTEGER",
        "response_mode": "ALTER TABLE attack_log ADD COLUMN response_mode VARCHAR(120)",
        "response_confidence": "ALTER TABLE attack_log ADD COLUMN response_confidence FLOAT",
        "intel_reputation": "ALTER TABLE attack_log ADD COLUMN intel_reputation VARCHAR(80)",
        "intel_confidence": "ALTER TABLE attack_log ADD COLUMN intel_confidence FLOAT",
        "intel_score": "ALTER TABLE attack_log ADD COLUMN intel_score INTEGER",
        "intel_summary": "ALTER TABLE attack_log ADD COLUMN intel_summary TEXT",
        "mitre_technique": "ALTER TABLE attack_log ADD COLUMN mitre_technique VARCHAR(160)",
        "mitre_tactic": "ALTER TABLE attack_log ADD COLUMN mitre_tactic VARCHAR(100)",
        "ioc_matches": "ALTER TABLE attack_log ADD COLUMN ioc_matches TEXT",
        "created_by_user_id": "ALTER TABLE attack_log ADD COLUMN created_by_user_id INTEGER",
    }

    for column, sql in migrations.items():
        if column not in columns:
            db.session.execute(text(sql))

    db.session.execute(
        text(
            "UPDATE attack_log SET event_source = 'simulation' "
            "WHERE event_source IS NULL OR event_source = ''"
        )
    )
    db.session.execute(
        text(
            "UPDATE attack_log SET event_status = 'analyzed' "
            "WHERE event_status IS NULL OR event_status = ''"
        )
    )
    db.session.execute(
        text(
            "UPDATE attack_log SET event_uuid = 'EVG-LEGACY-' || id "
            "WHERE event_uuid IS NULL OR event_uuid = ''"
        )
    )
    db.session.execute(
        text(
            "UPDATE attack_log SET attack_type = "
            "CASE "
            "WHEN lower(coalesce(attack_category, '') || ' ' || coalesce(attack_label, '')) LIKE '%normal%' THEN 'normal' "
            "WHEN lower(coalesce(attack_category, '') || ' ' || coalesce(attack_label, '')) LIKE '%dos%' THEN 'dos' "
            "WHEN lower(coalesce(attack_category, '') || ' ' || coalesce(attack_label, '')) LIKE '%ddos%' THEN 'dos' "
            "WHEN lower(coalesce(attack_category, '') || ' ' || coalesce(attack_label, '')) LIKE '%probe%' THEN 'probe' "
            "WHEN lower(coalesce(attack_category, '') || ' ' || coalesce(attack_label, '')) LIKE '%scan%' THEN 'probe' "
            "WHEN lower(coalesce(attack_category, '') || ' ' || coalesce(attack_label, '')) LIKE '%r2l%' THEN 'r2l' "
            "WHEN lower(coalesce(attack_category, '') || ' ' || coalesce(attack_label, '')) LIKE '%credential%' THEN 'r2l' "
            "WHEN lower(coalesce(attack_category, '') || ' ' || coalesce(attack_label, '')) LIKE '%u2r%' THEN 'u2r' "
            "WHEN lower(coalesce(attack_category, '') || ' ' || coalesce(attack_label, '')) LIKE '%privilege%' THEN 'u2r' "
            "ELSE 'normal' END "
            "WHERE attack_type IS NULL OR attack_type = ''"
        )
    )
    for sql in [
        "CREATE INDEX IF NOT EXISTS ix_attack_log_event_uuid ON attack_log (event_uuid)",
        "CREATE INDEX IF NOT EXISTS ix_attack_log_source_time ON attack_log (event_source, timestamp)",
        "CREATE INDEX IF NOT EXISTS ix_attack_log_risk_time ON attack_log (risk_level, timestamp)",
        "CREATE INDEX IF NOT EXISTS ix_attack_log_type_time ON attack_log (attack_type, timestamp)",
        "CREATE INDEX IF NOT EXISTS ix_attack_log_source_ip_time ON attack_log (source_ip, timestamp)",
    ]:
        db.session.execute(text(sql))

    db.session.commit()


def ensure_user_schema():
    if not db.engine.url.drivername.startswith("sqlite"):
        return

    columns = {
        row[1]
        for row in db.session.execute(text("PRAGMA table_info(evoguard_user)")).fetchall()
    }

    migrations = {
        "is_active": "ALTER TABLE evoguard_user ADD COLUMN is_active BOOLEAN DEFAULT 1 NOT NULL",
    }

    for column, sql in migrations.items():
        if column not in columns:
            db.session.execute(text(sql))

    db.session.execute(
        text(
            "UPDATE evoguard_user SET is_active = 1 "
            "WHERE is_active IS NULL"
        )
    )
    db.session.execute(
        text(
            "UPDATE evoguard_user SET role = 'Admin', access_level = 'Administrator' "
            "WHERE lower(coalesce(access_level, '')) = 'administrator'"
        )
    )
    db.session.execute(
        text(
            "UPDATE evoguard_user SET role = 'Viewer' "
            "WHERE role IS NULL OR role = ''"
        )
    )
    db.session.commit()


def seed_threat_intel_iocs():
    for item in DEFAULT_THREAT_IOCS:
        exists = ThreatIntelIOC.query.filter_by(
            indicator_type=item["indicator_type"],
            indicator_value=item["indicator_value"],
        ).first()

        if exists:
            continue

        db.session.add(
            ThreatIntelIOC(
                indicator_type=item["indicator_type"],
                indicator_value=item["indicator_value"],
                reputation=item["reputation"],
                confidence=item["confidence"],
                attack_category=item["attack_category"],
                source_name=item["source_name"],
                notes=item["notes"],
            )
        )

    db.session.commit()


def seed_default_user():
    if (
        not DEFAULT_ADMIN_USERNAME
        or not DEFAULT_ADMIN_PASSWORD
        or DEFAULT_ADMIN_USERNAME.startswith("your-private-")
        or DEFAULT_ADMIN_PASSWORD.startswith("your-private-")
    ):
        return

    if User.query.filter_by(username=DEFAULT_ADMIN_USERNAME).first():
        return

    db.session.add(
        User(
            username=DEFAULT_ADMIN_USERNAME,
            password_hash=generate_password_hash(DEFAULT_ADMIN_PASSWORD),
            role="Admin",
            access_level="Administrator",
        )
    )
    db.session.commit()


def requested_source(default="all"):
    source = (request.args.get("source") or default or "all").lower()
    return source if source in ["all", "live", "simulation"] else "all"


def requested_attack_type():
    attack_type = (
        request.args.get("attack_type")
        or request.args.get("type")
        or request.args.get("category")
        or ""
    ).lower()
    return attack_type if attack_type in AVAILABLE_ATTACK_TYPES else ""


def requested_risk_level():
    risk_level = (request.args.get("risk_level") or request.args.get("risk") or "").strip()
    allowed = {"Critical", "High", "Medium", "Low"}

    for level in allowed:
        if risk_level.lower() == level.lower():
            return level

    return ""


def parse_datetime_filter(raw_value, end_of_day=False):
    if not raw_value:
        return None

    value = str(raw_value).strip()
    formats = [
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
    ]

    for fmt in formats:
        try:
            parsed = datetime.strptime(value[:19], fmt)
            if fmt == "%Y-%m-%d" and end_of_day:
                return parsed.replace(hour=23, minute=59, second=59)
            return parsed
        except ValueError:
            continue

    return None


def filter_logs_by_source(query, source=None):
    selected_source = source or requested_source()

    if selected_source in ["live", "simulation"]:
        return query.filter(AttackLog.event_source == selected_source)

    return query


def apply_attack_history_filters(query, source=None):
    query = filter_logs_by_source(query, source)
    attack_type = requested_attack_type()
    risk_level = requested_risk_level()
    country = (request.args.get("country") or "").strip()
    source_ip = (request.args.get("ip") or request.args.get("source_ip") or "").strip()
    search_text = (request.args.get("q") or request.args.get("search") or "").strip()
    date_from = parse_datetime_filter(request.args.get("from") or request.args.get("date_from"))
    date_to = parse_datetime_filter(
        request.args.get("to") or request.args.get("date_to"),
        end_of_day=True,
    )

    if attack_type:
        query = query.filter(AttackLog.attack_type == attack_type)

    if risk_level:
        query = query.filter(AttackLog.risk_level == risk_level)

    if country:
        query = query.filter(AttackLog.source_country.ilike(f"%{country}%"))

    if source_ip:
        query = query.filter(AttackLog.source_ip.ilike(f"%{source_ip}%"))

    if date_from:
        query = query.filter(AttackLog.timestamp >= date_from)

    if date_to:
        query = query.filter(AttackLog.timestamp <= date_to)

    if search_text:
        like_query = f"%{search_text}%"
        query = query.filter(
            or_(
                AttackLog.event_uuid.ilike(like_query),
                AttackLog.attack_label.ilike(like_query),
                AttackLog.attack_category.ilike(like_query),
                AttackLog.risk_level.ilike(like_query),
                AttackLog.source_country.ilike(like_query),
                AttackLog.source_ip.ilike(like_query),
                AttackLog.source_activity.ilike(like_query),
                AttackLog.explanation.ilike(like_query),
            )
        )

    return query


def pagination_args(default_limit=50, max_limit=200):
    page = max(request.args.get("page", default=1, type=int), 1)
    limit = min(max(request.args.get("limit", default=default_limit, type=int), 1), max_limit)
    return page, limit


def paginate_query(query, serializer, default_limit=50, max_limit=200):
    page, limit = pagination_args(default_limit, max_limit)
    total = query.count()
    items = (
        query.offset((page - 1) * limit)
        .limit(limit)
        .all()
    )

    return {
        "page": page,
        "limit": limit,
        "total": total,
        "pages": (total + limit - 1) // limit if total else 0,
        "has_next": page * limit < total,
        "has_prev": page > 1,
        "items": [serializer(item) for item in items],
    }


def initialize_database(flask_app):
    with flask_app.app_context():
        db.create_all()
        ensure_attacklog_schema()
        ensure_user_schema()
        seed_default_user()
        seed_threat_intel_iocs()


def serialize_attack_log(log):
    latest_analysis = normalize_analysis(agentic_analysis(log.attack_label))
    country = log.source_country or "Database"
    ip = log.source_ip or "Stored event"
    activity = log.source_activity or "Stored event"
    response_logs = (
        AIResponseLog.query.filter_by(attack_id=log.id)
        .order_by(AIResponseLog.timestamp.asc(), AIResponseLog.id.asc())
        .all()
    )
    serialized_responses = [serialize_ai_response_log(item) for item in response_logs]
    response_statuses = {item["status"] for item in serialized_responses}
    category_key = category_key_from_text(log.attack_category, log.attack_label)
    mitre = mitre_for_category(category_key)
    ioc_matches = safe_json_list(log.ioc_matches)
    threat_intel = {
        "reputation": log.intel_reputation or "No IOC Match",
        "confidence": log.intel_confidence or 0,
        "score": log.intel_score or log.risk_score or 0,
        "summary": log.intel_summary or f"No stored IOC match. MITRE mapping: {mitre['technique']}.",
        "mitre_technique": log.mitre_technique or mitre["technique"],
        "mitre_tactic": log.mitre_tactic or mitre["tactic"],
        "mitre_priority": mitre["priority"],
        "ioc_matches": ioc_matches,
        "ioc_match_count": len(ioc_matches),
    }

    return {
        "id": log.id,
        "event_uuid": log.event_uuid or f"EVG-LEGACY-{log.id}",
        "attack_label": log.attack_label,
        "attack_category": log.attack_category,
        "attack_type": category_key,
        "risk_score": log.risk_score,
        "risk_level": log.risk_level,
        "explanation": log.explanation,
        "timestamp": log.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "event_source": log.event_source or "simulation",
        "event_status": log.event_status or "analyzed",
        "country": country,
        "source_country": country,
        "ip": ip,
        "source_ip": ip,
        "source_activity": activity,
        "sensor_name": log.sensor_name or "Manual Live Intake",
        "target_asset": log.target_asset or "UAE Protected Network",
        "network_protocol": log.network_protocol or "tcp",
        "destination_port": log.destination_port,
        "created_by_user_id": log.created_by_user_id,
        "has_raw_payload": bool(log.raw_payload),
        "response_mode": log.response_mode or latest_analysis["response_mode"],
        "response_confidence": (
            log.response_confidence
            if log.response_confidence is not None
            else latest_analysis["response_confidence"]
        ),
        "threat_intel": threat_intel,
        "intel_reputation": threat_intel["reputation"],
        "intel_confidence": threat_intel["confidence"],
        "mitre_technique": threat_intel["mitre_technique"],
        "mitre_tactic": threat_intel["mitre_tactic"],
        "recommended_actions": latest_analysis["recommended_actions"],
        "response_actions": serialized_responses,
        "ai_response": {
            "status": (
                "Contained"
                if "Executed" in response_statuses
                else "Monitoring"
                if "Monitoring" in response_statuses
                else "Pending"
            ),
            "actions_executed": sum(
                1 for item in serialized_responses if item["status"] == "Executed"
            ),
            "actions_total": len(serialized_responses),
            "latest_stage": (
                serialized_responses[-1]["execution_stage"]
                if serialized_responses
                else "Pending"
            ),
        },
    }
def category_key_for_log(log):
    if log.attack_type in AVAILABLE_ATTACK_TYPES:
        return log.attack_type

    return category_key_from_text(log.attack_category, log.attack_label)


def threat_intel_payload(source="live"):
    logs = (
        filter_logs_by_source(
            AttackLog.query.order_by(AttackLog.timestamp.desc(), AttackLog.id.desc()),
            source,
        )
        .limit(100)
        .all()
    )
    iocs = (
        ThreatIntelIOC.query.order_by(
            ThreatIntelIOC.confidence.desc(),
            ThreatIntelIOC.last_seen.desc(),
        )
        .limit(50)
        .all()
    )
    summary = threat_intel_summary_for_logs(logs)
    source_summary = {}

    for log in logs:
        key = log.source_ip or log.source_country or "Unknown"
        current = source_summary.get(
            key,
            {
                "indicator": key,
                "country": log.source_country or "Unknown",
                "events": 0,
                "max_risk": 0,
                "reputation": log.intel_reputation or "No IOC Match",
                "latest_category": log.attack_category,
            },
        )
        current["events"] += 1
        current["max_risk"] = max(current["max_risk"], log.risk_score or 0)
        if log.intel_reputation and log.intel_reputation != "No IOC Match":
            current["reputation"] = log.intel_reputation
        current["latest_category"] = log.attack_category or current["latest_category"]
        source_summary[key] = current

    mitre_techniques = [
        {
            "technique": technique,
            "events": count,
            "tactic": next(
                (
                    value["tactic"]
                    for value in MITRE_ATTACK_MAPPING.values()
                    if value["technique"] == technique
                ),
                "Unknown",
            ),
        }
        for technique, count in summary["mitre_counts"].items()
    ]

    if not mitre_techniques:
        mitre_techniques = [
            {
                "technique": value["technique"],
                "events": 0,
                "tactic": value["tactic"],
            }
            for value in MITRE_ATTACK_MAPPING.values()
        ]

    recommendations = [
        "Prioritize IOC-matched live events before generic simulation noise.",
        "Use MITRE technique mapping to explain why the AI chose each response.",
        "Raise response priority for repeated source IPs and malicious reputation.",
    ]

    return {
        "source": source,
        "summary": summary,
        "iocs": [serialize_ioc(ioc) for ioc in iocs],
        "top_sources": sorted(
            source_summary.values(),
            key=lambda item: (item["max_risk"], item["events"]),
            reverse=True,
        )[:8],
        "mitre_techniques": sorted(
            mitre_techniques,
            key=lambda item: item["events"],
            reverse=True,
        ),
        "recent_enriched": [serialize_attack_log(log) for log in logs[:8]],
        "recommendations": recommendations,
    }


def build_assistant_answer(question):
    normalized_question = (question or "").lower()
    latest_attack = AttackLog.query.order_by(AttackLog.timestamp.desc()).first()
    live_logs = filter_logs_by_source(
        AttackLog.query.order_by(AttackLog.timestamp.desc()),
        "live",
    ).all()
    all_logs = AttackLog.query.order_by(AttackLog.timestamp.desc()).all()

    if "latest" in normalized_question or "last" in normalized_question:
        if not latest_attack:
            return "No attacks have been recorded yet."

        serialized = serialize_attack_log(latest_attack)
        return (
            f"Latest event: {serialized['attack_category']} from {serialized['country']} "
            f"({serialized['ip']}). Risk is {serialized['risk_level']} with score "
            f"{serialized['risk_score']}/100. Threat intel verdict: "
            f"{serialized['threat_intel']['reputation']}."
        )

    if "mitre" in normalized_question or "attack framework" in normalized_question:
        if not latest_attack:
            return "No MITRE mapping is available yet because no events have been recorded."

        serialized = serialize_attack_log(latest_attack)
        return (
            f"The latest event maps to {serialized['threat_intel']['mitre_technique']} "
            f"under the {serialized['threat_intel']['mitre_tactic']} tactic. "
            f"Priority: {serialized['threat_intel']['mitre_priority']}"
        )

    if "ioc" in normalized_question or "threat intel" in normalized_question or "reputation" in normalized_question:
        payload = threat_intel_payload("live")
        summary = payload["summary"]
        return (
            f"Threat intel has enriched {summary['enriched_events']} live event(s), "
            f"with {summary['ioc_matches']} IOC match(es), "
            f"{summary['malicious_events']} malicious/high-risk event(s), and "
            f"{summary['watchlist_events']} watchlist event(s)."
        )

    if "contain" in normalized_question or "block" in normalized_question or "response" in normalized_question:
        if not latest_attack:
            return "No containment workflow exists yet. Send a live event or run a simulation first."

        responses = AIResponseLog.query.filter_by(attack_id=latest_attack.id).all()
        executed = [item.action_name for item in responses if item.status == "Executed"]
        monitoring = [item.action_name for item in responses if item.status == "Monitoring"]
        actions = executed or monitoring

        return (
            f"EvoGuard AI generated {len(responses)} response action(s) for the latest "
            f"{latest_attack.attack_category} event. Current actions: "
            f"{'; '.join(actions[:4]) if actions else 'No actions generated yet.'}"
        )

    if "risk" in normalized_question:
        critical_count = sum(1 for log in all_logs if log.risk_level == "Critical")
        high_count = sum(1 for log in all_logs if log.risk_level == "High")
        score = calculate_ai_defense_score(all_logs)
        return (
            f"EvoGuard currently has {critical_count} critical alert(s), "
            f"{high_count} high-risk event(s), and an AI Defense Score of "
            f"{score['score_display']}."
        )

    if "report" in normalized_question:
        return (
            "The report engine is ready. Use the Reports page or /download_report "
            "to export an enriched PDF with incidents, AI response actions, IOC data, "
            "and MITRE mappings."
        )

    if "test" in normalized_question or "send event" in normalized_question or "live event" in normalized_question:
        return (
            "Use the Attack Map live intake panel, /test_live_event/<type>, "
            "/bulk_ingest_events, /ingest_csv, or backend/tools/send_live_event.py "
            "to send real-style events into EvoGuard."
        )

    if "status" in normalized_question or "health" in normalized_question:
        return (
            f"Backend is online. Live events stored: {len(live_logs)}. "
            f"Realtime mode is {'enabled' if realtime_enabled() else 'using polling fallback'}. "
            f"Threat intel IOC records: {ThreatIntelIOC.query.count()}."
        )

    if "summary" in normalized_question or not normalized_question:
        total = AttackLog.query.count()
        live_count = AttackLog.query.filter_by(event_source="live").count()
        simulation_count = AttackLog.query.filter_by(event_source="simulation").count()
        return (
            f"EvoGuard has recorded {total} total security event(s): {live_count} live "
            f"event(s) and {simulation_count} simulation event(s). The backend is using "
            "AI detection, threat-intel enrichment, autonomous response execution, "
            "and realtime dashboard updates."
        )

    return (
        "I can answer commands like latest attack, risk summary, MITRE mapping, "
        "IOC reputation, containment actions, report status, system health, and how "
        "to send live test events."
    )

def system_health_payload():
    checks = {
        "database": "unknown",
        "ai_artifacts": "ready",
        "socketio": "enabled" if realtime_enabled() else "disabled",
        "reports": "ready",
    }

    try:
        db.session.execute(text("SELECT 1"))
        checks["database"] = "ready"
    except Exception:
        checks["database"] = "error"

    missing_artifacts = [
        os.path.basename(path)
        for path in [MODEL_PATH, ENCODER_PATH, FEATURE_PATH]
        if not os.path.exists(path)
    ]

    if missing_artifacts:
        checks["ai_artifacts"] = "missing"

    try:
        os.makedirs(REPORT_DIR, exist_ok=True)
        checks["reports"] = "ready"
    except OSError:
        checks["reports"] = "error"

    status = (
        "healthy"
        if all(value in {"ready", "enabled", "disabled"} for value in checks.values())
        else "degraded"
    )

    return {
        "system": "EvoGuard Enterprise",
        "status": status,
        "timestamp": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "environment": os.getenv("EVOGUARD_APP_ENV", "development"),
        "checks": checks,
        "missing_artifacts": missing_artifacts,
        "database": db.engine.url.drivername,
        "cors_origins": configured_cors_origins(),
        "scheduler_enabled": env_bool("EVOGUARD_ENABLE_SCHEDULER", False),
        "max_upload_mb": env_int("EVOGUARD_MAX_UPLOAD_MB", 8, minimum=1, maximum=64),
    }


def database_summary_payload():
    live_count = AttackLog.query.filter_by(event_source="live").count()
    simulation_count = AttackLog.query.filter_by(event_source="simulation").count()

    return {
        "database": db.engine.url.drivername,
        "phase": "Phase 3 - Database Upgrade",
        "tables": {
            "attack_logs": AttackLog.query.count(),
            "ai_response_logs": AIResponseLog.query.count(),
            "users": User.query.count(),
            "threat_intel_iocs": ThreatIntelIOC.query.count(),
            "audit_logs": SystemAuditLog.query.count(),
            "report_logs": ReportGenerationLog.query.count(),
        },
        "event_sources": {
            "live": live_count,
            "simulation": simulation_count,
            "all": live_count + simulation_count,
        },
        "supported_filters": [
            "source",
            "attack_type",
            "risk_level",
            "country",
            "source_ip",
            "from",
            "to",
            "q",
            "page",
            "limit",
            "sort",
        ],
        "postgres_ready": db.engine.url.drivername.startswith("postgresql"),
        "external_ingest_api_key_enabled": bool(INGEST_API_KEY),
    }


def register_routes(app):
    @app.route("/")
    def home():
        if desktop_frontend_enabled():
            return serve_frontend_asset("index.html")

        return jsonify(
            {
                "system": "EvoGuard Enterprise",
                "status": "Backend API is running",
                "available_attacks": AVAILABLE_ATTACK_TYPES,
                "health_endpoint": "/health",
                "docs": {
                    "live_event_examples": "/live_event_examples",
                    "realtime_status": "/realtime_status",
                    "database_summary": "/database/summary",
                    "audit_logs": "/audit_logs",
                    "report_history": "/report_history",
                    "model_metrics": "/model_metrics",
                },
            }
        )

    @app.route("/health")
    @app.route("/api/health")
    def health():
        payload = system_health_payload()
        status_code = 200 if payload["status"] == "healthy" else 503
        return jsonify(payload), status_code

    @app.route("/readiness")
    @app.route("/api/readiness")
    def readiness():
        payload = system_health_payload()
        ready = (
            payload["checks"]["database"] == "ready"
            and payload["checks"]["ai_artifacts"] == "ready"
        )
        return jsonify({**payload, "ready": ready}), 200 if ready else 503

    @app.route("/auth/session")
    def auth_session():
        user = current_user()

        if user and not user.is_active:
            session.clear()
            user = None

        return jsonify(
            {
                "authenticated": user is not None,
                "user": serialize_user(user),
            }
        )

    @app.route("/auth/login", methods=["POST"])
    def auth_login():
        payload = request.get_json(silent=True) or {}
        username = str(payload.get("username") or "").strip()
        password = str(payload.get("password") or "")

        if not username or not password:
            return api_error("Username and password are required.", 400)

        user = User.query.filter_by(username=username).first()

        if not user or not check_password_hash(user.password_hash, password):
            return api_error("Invalid username or password.", 401)

        if not user.is_active:
            return api_error("Account disabled.", 403)

        user.last_login = datetime.utcnow()
        db.session.commit()
        session["user_id"] = user.id
        log_audit_action(
            "operator_login",
            entity_type="user",
            entity_id=user.id,
            details={"username": user.username},
        )

        return jsonify(
            {
                "authenticated": True,
                "user": serialize_user(user),
            }
        )

    @app.route("/auth/logout", methods=["POST"])
    def auth_logout():
        user = current_user()
        if user:
            log_audit_action(
                "operator_logout",
                entity_type="user",
                entity_id=user.id,
                details={"username": user.username},
            )
        session.clear()
        return jsonify({"authenticated": False, "status": "logged_out"})

    @app.route("/users")
    @admin_required
    def users():
        rows = User.query.order_by(User.created_at.asc(), User.id.asc()).all()
        return jsonify(
            {
                "roles": USER_ROLES,
                "users": [serialize_user(user) for user in rows],
            }
        )

    @app.route("/users", methods=["POST"])
    @admin_required
    def create_user():
        payload = request.get_json(silent=True) or {}
        username = str(payload.get("username") or "").strip()
        password = str(payload.get("password") or "")
        role = normalize_user_role(payload.get("role") or "Viewer")

        if len(username) < 3:
            return api_error("Username must be at least 3 characters.", 400)

        if len(password) < 8:
            return api_error("Password must be at least 8 characters.", 400)

        if User.query.filter_by(username=username).first():
            return api_error("Username already exists.", 409)

        new_user = User(
            username=username,
            password_hash=generate_password_hash(password),
            role=role,
            access_level=access_level_for_role(role),
            is_active=True,
        )
        db.session.add(new_user)
        db.session.flush()
        log_audit_action(
            "user_created",
            entity_type="user",
            entity_id=new_user.id,
            details={"username": new_user.username, "role": new_user.role},
        )
        db.session.commit()

        return jsonify({"status": "created", "user": serialize_user(new_user)}), 201

    @app.route("/users/<int:user_id>/role", methods=["PATCH"])
    @admin_required
    def update_user_role(user_id):
        target_user = db.session.get(User, user_id)

        if not target_user:
            return api_error("User not found.", 404)

        payload = request.get_json(silent=True) or {}
        role = normalize_user_role(payload.get("role"))

        if target_user.id == current_user_id() and role != "Admin":
            return api_error("You cannot remove your own Admin role.", 400)

        target_user.role = role
        target_user.access_level = access_level_for_role(role)
        log_audit_action(
            "user_role_updated",
            entity_type="user",
            entity_id=target_user.id,
            details={"username": target_user.username, "role": role},
        )
        db.session.commit()

        return jsonify({"status": "updated", "user": serialize_user(target_user)})

    @app.route("/users/<int:user_id>/password", methods=["PATCH"])
    @admin_required
    def update_user_password(user_id):
        target_user = db.session.get(User, user_id)

        if not target_user:
            return api_error("User not found.", 404)

        payload = request.get_json(silent=True) or {}
        password = str(payload.get("password") or "")

        if len(password) < 8:
            return api_error("Password must be at least 8 characters.", 400)

        target_user.password_hash = generate_password_hash(password)
        log_audit_action(
            "user_password_reset",
            entity_type="user",
            entity_id=target_user.id,
            details={"username": target_user.username},
        )
        db.session.commit()

        return jsonify({"status": "password_updated", "user": serialize_user(target_user)})

    @app.route("/users/<int:user_id>/status", methods=["PATCH"])
    @admin_required
    def update_user_status(user_id):
        target_user = db.session.get(User, user_id)

        if not target_user:
            return api_error("User not found.", 404)

        payload = request.get_json(silent=True) or {}
        is_active = bool(payload.get("is_active"))

        if target_user.id == current_user_id() and not is_active:
            return api_error("You cannot disable your own account.", 400)

        target_user.is_active = is_active
        log_audit_action(
            "user_status_updated",
            entity_type="user",
            entity_id=target_user.id,
            details={"username": target_user.username, "is_active": is_active},
        )
        db.session.commit()

        return jsonify({"status": "updated", "user": serialize_user(target_user)})

    @app.route("/users/<int:user_id>", methods=["DELETE"])
    @admin_required
    def delete_user(user_id):
        target_user = db.session.get(User, user_id)

        if not target_user:
            return api_error("User not found.", 404)

        if target_user.id == current_user_id():
            return api_error("You cannot delete your own active account.", 400)

        deleted_username = target_user.username
        AttackLog.query.filter_by(created_by_user_id=user_id).update(
            {"created_by_user_id": None},
            synchronize_session=False,
        )
        SystemAuditLog.query.filter_by(actor_user_id=user_id).update(
            {"actor_user_id": None},
            synchronize_session=False,
        )
        ReportGenerationLog.query.filter_by(generated_by_user_id=user_id).update(
            {"generated_by_user_id": None},
            synchronize_session=False,
        )
        db.session.delete(target_user)
        log_audit_action(
            "user_deleted",
            entity_type="user",
            entity_id=user_id,
            details={"username": deleted_username},
        )
        db.session.commit()

        return jsonify(
            {
                "status": "deleted",
                "deleted_user_id": user_id,
                "deleted_username": deleted_username,
            }
        )

    @app.route("/dashboard_stats")
    @login_required
    def dashboard_stats():
        source = requested_source("all")
        return jsonify(dashboard_stats_payload(source))

    @app.route("/realtime_status")
    @login_required
    def realtime_status():
        return jsonify(realtime_status_payload(requested_source("live")))

    @app.route("/ai_defense_score")
    @login_required
    def ai_defense_score():
        source = requested_source("all")
        logs = filter_logs_by_source(
            AttackLog.query.order_by(AttackLog.timestamp.desc()),
            source,
        ).all()
        return jsonify(calculate_ai_defense_score(logs))

    @app.route("/ai_responses")
    @login_required
    def ai_responses():
        limit = min(request.args.get("limit", default=30, type=int), 100)
        source = requested_source("all")
        attack_id = request.args.get("attack_id", type=int)

        query = AIResponseLog.query.join(AttackLog, AIResponseLog.attack_id == AttackLog.id)

        if attack_id:
            query = query.filter(AIResponseLog.attack_id == attack_id)

        if source in ["live", "simulation"]:
            query = query.filter(AttackLog.event_source == source)

        response_logs = (
            query.order_by(AIResponseLog.timestamp.desc(), AIResponseLog.id.desc())
            .limit(limit)
            .all()
        )

        return jsonify(
            {
                "source": source,
                "count": len(response_logs),
                "responses": [serialize_ai_response_log(item) for item in response_logs],
            }
        )

    @app.route("/ai_response_summary")
    @login_required
    def ai_response_summary():
        source = requested_source("all")
        logs = filter_logs_by_source(
            AttackLog.query.order_by(AttackLog.timestamp.desc()),
            source,
        ).all()
        return jsonify(response_summary_for_logs(logs))

    @app.route("/ai_response_playbook")
    @login_required
    def ai_response_playbook():
        return jsonify(
            {
                "automation_mode": "Autonomous AI",
                "human_approval_required": False,
                "safety_note": (
                    "Actions are simulated for the senior project prototype and do not "
                    "change real firewall, endpoint, or identity systems."
                ),
                "playbooks": AI_RESPONSE_PLAYBOOK,
            }
        )

    @app.route("/autonomous_response_plan/<int:attack_id>")
    @login_required
    def autonomous_response_plan(attack_id):
        attack_log = db.session.get(AttackLog, attack_id)

        if not attack_log:
            return api_error("Attack record not found.", 404)

        category = category_key_for_log(attack_log)
        response_logs = (
            AIResponseLog.query.filter_by(attack_id=attack_log.id)
            .order_by(AIResponseLog.timestamp.asc(), AIResponseLog.id.asc())
            .all()
        )

        return jsonify(
            {
                "attack": serialize_attack_log(attack_log),
                "playbook": AI_RESPONSE_PLAYBOOK.get(category, AI_RESPONSE_PLAYBOOK["normal"]),
                "summary": response_summary_for_logs([attack_log]),
                "responses": [serialize_ai_response_log(item) for item in response_logs],
            }
        )

    @app.route("/threat_intel")
    @login_required
    def threat_intel():
        source = requested_source("live")
        return jsonify(threat_intel_payload(source))

    @app.route("/ioc_lookup/<path:indicator>")
    @login_required
    def ioc_lookup(indicator):
        normalized_indicator = indicator.strip()

        if not normalized_indicator:
            return api_error("Indicator is required.", 400)

        like_indicator = f"%{normalized_indicator}%"
        iocs = (
            ThreatIntelIOC.query.filter(
                or_(
                    ThreatIntelIOC.indicator_value.ilike(like_indicator),
                    ThreatIntelIOC.indicator_type.ilike(like_indicator),
                    ThreatIntelIOC.reputation.ilike(like_indicator),
                    ThreatIntelIOC.attack_category.ilike(like_indicator),
                    ThreatIntelIOC.source_name.ilike(like_indicator),
                    ThreatIntelIOC.notes.ilike(like_indicator),
                )
            )
            .order_by(ThreatIntelIOC.confidence.desc(), ThreatIntelIOC.last_seen.desc())
            .limit(25)
            .all()
        )
        logs = (
            AttackLog.query.filter(
                or_(
                    AttackLog.source_ip.ilike(like_indicator),
                    AttackLog.source_country.ilike(like_indicator),
                    AttackLog.attack_category.ilike(like_indicator),
                    AttackLog.attack_label.ilike(like_indicator),
                    AttackLog.intel_reputation.ilike(like_indicator),
                    AttackLog.mitre_technique.ilike(like_indicator),
                )
            )
            .order_by(AttackLog.timestamp.desc(), AttackLog.id.desc())
            .limit(20)
            .all()
        )

        return jsonify(
            {
                "indicator": normalized_indicator,
                "match_count": len(iocs),
                "event_count": len(logs),
                "matches": [serialize_ioc(ioc) for ioc in iocs],
                "related_events": [serialize_attack_log(log) for log in logs],
                "recommendation": (
                    "Treat this indicator as high priority and review related AI actions."
                    if any(ioc.reputation in ["Malicious", "Critical", "High Risk"] for ioc in iocs)
                    else "No critical IOC match found. Continue monitoring related events."
                ),
                "verdict": (
                    iocs[0].reputation
                    if iocs
                    else "Observed" if logs else "Unknown"
                ),
            }
        )

    @app.route("/model_metrics")
    @login_required
    def model_metrics():
        return jsonify(load_model_metrics())

    @app.route("/database_summary")
    @app.route("/database/summary")
    @login_required
    def database_summary():
        return jsonify(database_summary_payload())

    @app.route("/audit_logs")
    @login_required
    def audit_logs():
        limit = min(request.args.get("limit", default=50, type=int), 200)
        logs = (
            SystemAuditLog.query.order_by(SystemAuditLog.timestamp.desc(), SystemAuditLog.id.desc())
            .limit(limit)
            .all()
        )
        return jsonify(
            {
                "count": len(logs),
                "logs": [serialize_audit_log(log) for log in logs],
            }
        )

    @app.route("/report_history")
    @login_required
    def report_history():
        limit = min(request.args.get("limit", default=30, type=int), 100)
        logs = (
            ReportGenerationLog.query.order_by(
                ReportGenerationLog.generated_at.desc(),
                ReportGenerationLog.id.desc(),
            )
            .limit(limit)
            .all()
        )
        return jsonify(
            {
                "count": len(logs),
                "reports": [serialize_report_log(log) for log in logs],
            }
        )

    @app.route("/simulate_attack", methods=["POST"])
    @login_required
    def simulate_attack_default():
        return simulate_attack_by_type("dos")

    @app.route("/simulate_attack/<attack_type>", methods=["POST"])
    @login_required
    def simulate_attack_by_type(attack_type):
        attack_type = attack_type.lower()

        if attack_type not in AVAILABLE_ATTACK_TYPES:
            return api_error(
                "Invalid attack type",
                400,
                available_types=AVAILABLE_ATTACK_TYPES,
            )

        sample_data = get_sample_data(attack_type)
        analysis = predict_and_log(sample_data, attack_type)

        return jsonify(analysis)

    @app.route("/ingest_event", methods=["POST"])
    @app.route("/live_event", methods=["POST"])
    @ingest_auth_required
    def ingest_event():
        payload = request.get_json(silent=True) or {}
        return jsonify(create_live_attack_log(payload)), 201

    @app.route("/bulk_ingest_events", methods=["POST"])
    @ingest_auth_required
    def bulk_ingest_events():
        payload = request.get_json(silent=True) or {}
        raw_events = payload.get("events") or []

        if not isinstance(raw_events, list) or not raw_events:
            return api_error("Send JSON with a non-empty events list.", 400)

        created = []
        errors = []

        for index, raw_event in enumerate(raw_events, start=1):
            try:
                created.append(create_live_attack_log(normalize_bulk_event(raw_event)))
            except Exception as error:
                db.session.rollback()
                errors.append({"index": index, "message": str(error)})

        return jsonify(
            {
                "status": "processed",
                "received": len(raw_events),
                "created": len(created),
                "failed": len(errors),
                "events": created,
                "errors": errors,
            }
        ), 207 if errors else 201

    @app.route("/ingest_csv", methods=["POST"])
    @ingest_auth_required
    def ingest_csv():
        csv_text = ""

        if "file" in request.files:
            csv_text = request.files["file"].read().decode("utf-8")
        else:
            payload = request.get_json(silent=True) or {}
            csv_text = payload.get("csv") or request.get_data(as_text=True)

        if not csv_text.strip():
            return api_error("CSV content is required.", 400)

        events = parse_csv_events(csv_text)

        if not events:
            return api_error("CSV did not contain any valid event rows.", 400)

        created = [create_live_attack_log(event) for event in events]

        return jsonify(
            {
                "status": "processed",
                "created": len(created),
                "events": created,
                "expected_columns": [
                    "attack_type",
                    "attack_label",
                    "country",
                    "ip",
                    "source_activity",
                    "sensor_name",
                    "target_asset",
                    "network_protocol",
                    "destination_port",
                ],
            }
        ), 201

    @app.route("/live_event_examples")
    @login_required
    def live_event_examples():
        examples = {
            event_type: {
                **events[0],
                "attack_type": event_type,
                "ip": "203.0.113.77",
            }
            for event_type, events in LIVE_TEST_EVENT_LIBRARY.items()
        }

        return jsonify(
            {
                "status": "ready",
                "message": "Use these examples to send live events into EvoGuard.",
                "endpoint": "/ingest_event",
                "bulk_endpoint": "/bulk_ingest_events",
                "csv_endpoint": "/ingest_csv",
                "supported_types": list(LIVE_TEST_EVENT_LIBRARY.keys()),
                "auth": {
                    "browser_session": "Log in through the EvoGuard frontend.",
                    "api_key_header": "X-EvoGuard-Ingest-Key",
                    "bearer_header": "Authorization: Bearer <EVOGUARD_INGEST_API_KEY>",
                    "api_key_enabled": bool(INGEST_API_KEY),
                },
                "examples": examples,
                "powershell_example": (
                    "Invoke-RestMethod -Method POST -Uri http://127.0.0.1:5000/ingest_event "
                    "-ContentType 'application/json' "
                    "-Headers @{ 'X-EvoGuard-Ingest-Key' = $env:EVOGUARD_INGEST_API_KEY } "
                    "-Body '{\"attack_type\":\"dos\",\"country\":\"Russia\","
                    "\"ip\":\"203.0.113.77\","
                    "\"sensor_name\":\"Edge IDS\",\"target_asset\":\"Public Web Gateway\","
                    "\"network_protocol\":\"tcp\",\"destination_port\":443,"
                    "\"source_activity\":\"High-volume TCP flood\"}'"
                ),
                "python_tool_example": "python backend/tools/send_live_event.py --type dos --count 1",
                "csv_tool_example": "python backend/tools/send_csv_events.py data/sample_live_events.csv",
            }
        )

    @app.route("/test_live_event", defaults={"event_type": "random"}, methods=["POST"])
    @app.route("/test_live_event/<event_type>", methods=["POST"])
    @login_required
    def test_live_event(event_type):
        event_type = (event_type or "random").lower()

        if event_type != "random" and event_type not in LIVE_TEST_EVENT_LIBRARY:
            return api_error(
                "Invalid live test event type",
                400,
                available_types=["random", *LIVE_TEST_EVENT_LIBRARY.keys()],
            )

        payload = build_live_test_payload(event_type)
        overrides = request.get_json(silent=True) or {}
        payload.update(
            {
                key: value
                for key, value in overrides.items()
                if value not in [None, ""]
            }
        )

        result = create_live_attack_log(payload)
        return jsonify({**result, "test_payload": payload}), 201

    @app.route("/attack_history")
    @login_required
    def attack_history():
        source = requested_source("all")
        sort = (request.args.get("sort") or "timestamp_desc").lower()
        query = apply_attack_history_filters(AttackLog.query, source)

        if sort == "risk_desc":
            query = query.order_by(AttackLog.risk_score.desc(), AttackLog.timestamp.desc())
        elif sort == "risk_asc":
            query = query.order_by(AttackLog.risk_score.asc(), AttackLog.timestamp.desc())
        elif sort == "timestamp_asc":
            query = query.order_by(AttackLog.timestamp.asc(), AttackLog.id.asc())
        else:
            query = query.order_by(AttackLog.timestamp.desc(), AttackLog.id.desc())

        page = paginate_query(query, serialize_attack_log)

        return jsonify(
            {
                "source": source,
                "filters": {
                    "attack_type": requested_attack_type() or None,
                    "risk_level": requested_risk_level() or None,
                    "country": request.args.get("country"),
                    "source_ip": request.args.get("ip") or request.args.get("source_ip"),
                    "search": request.args.get("q") or request.args.get("search"),
                    "date_from": request.args.get("from") or request.args.get("date_from"),
                    "date_to": request.args.get("to") or request.args.get("date_to"),
                    "sort": sort,
                },
                "pagination": {
                    key: value
                    for key, value in page.items()
                    if key != "items"
                },
                "history": page["items"],
            }
        )
    @app.route("/reset_attack_history", methods=["GET", "POST", "DELETE"])
    @app.route("/clear_attack_history", methods=["GET", "POST", "DELETE"])
    @login_required
    def reset_attack_history():
        source = requested_source("all")
        live_records = AttackLog.query.filter_by(event_source="live").count()
        simulation_records = AttackLog.query.filter_by(event_source="simulation").count()

        if request.method == "GET":
            return jsonify(
                {
                    "status": "confirmation_required",
                    "message": "Use POST or DELETE with confirm=RESET to clear records.",
                    "source": source,
                    "examples": [
                        "/reset_attack_history?source=live&confirm=RESET",
                        "/reset_attack_history?source=simulation&confirm=RESET",
                        "/reset_attack_history?source=all&confirm=RESET",
                    ],
                    "current_records": AttackLog.query.count(),
                    "live_records": live_records,
                    "simulation_records": simulation_records,
                }
            )

        if parse_reset_confirmation() != "RESET":
            return api_error(
                "Reset not confirmed. Send confirm=RESET to clear attack history.",
                400,
                required_confirm="RESET",
            )

        attack_ids = [
            row[0]
            for row in filter_logs_by_source(
                AttackLog.query.with_entities(AttackLog.id),
                source,
            ).all()
        ]

        if attack_ids:
            AIResponseLog.query.filter(AIResponseLog.attack_id.in_(attack_ids)).delete(
                synchronize_session=False
            )

        delete_query = filter_logs_by_source(AttackLog.query, source)
        deleted_records = delete_query.delete(synchronize_session=False)
        db.session.commit()
        log_audit_action(
            "attack_history_reset",
            entity_type="attack_log",
            event_source=source,
            details={"deleted_records": deleted_records},
        )
        broadcast_history_reset(source, deleted_records)

        remaining_logs = filter_logs_by_source(
            AttackLog.query.order_by(AttackLog.timestamp.desc()),
            source,
        ).all()

        return jsonify(
            {
                "status": "success",
                "message": f"Attack history cleared for source={source}.",
                "source": source,
                "deleted_records": deleted_records,
                "total_threats": AttackLog.query.count(),
                "ai_defense_score": calculate_ai_defense_score(remaining_logs),
            }
        )
    @app.route("/search")
    @login_required
    def search():
        query_text = (
            request.args.get("q")
            or request.args.get("query")
            or ""
        ).strip()
        limit = min(request.args.get("limit", default=12, type=int), 50)
        source = requested_source("all")

        if not query_text:
            return jsonify({"query": query_text, "source": source, "results": []})

        page_catalog = [
            {
                "type": "Page",
                "title": "Dashboard",
                "subtitle": "Live AI defense dashboard, received attacks, AI defense score, and device telemetry.",
                "page": "Dashboard",
            },
            {
                "type": "Page",
                "title": "Threat Intel",
                "subtitle": "Threat severity, source intelligence, category trends, and AI recommendations.",
                "page": "Threat Intel",
            },
            {
                "type": "Page",
                "title": "Attack Map",
                "subtitle": "Live backend attack origins and protected UAE target route tracking.",
                "page": "Attack Map",
            },
            {
                "type": "Page",
                "title": "Simulation",
                "subtitle": "Controlled attack tests, simulation routes, and autonomous AI response lab.",
                "page": "Simulation",
            },
            {
                "type": "Page",
                "title": "Reports",
                "subtitle": "Incident, weekly, monthly, and yearly EvoGuard security reports.",
                "page": "Reports",
            },
            {
                "type": "Page",
                "title": "Settings",
                "subtitle": "Operator profile, AI engine status, platform health, and notification settings.",
                "page": "Settings",
            },
        ]

        lowered_query = query_text.lower()
        results = [
            page
            for page in page_catalog
            if lowered_query
            in f"{page['type']} {page['title']} {page['subtitle']} {page['page']}".lower()
        ][:limit]

        like_query = f"%{query_text}%"
        filters = [
            AttackLog.attack_label.ilike(like_query),
            AttackLog.attack_category.ilike(like_query),
            AttackLog.risk_level.ilike(like_query),
            AttackLog.explanation.ilike(like_query),
            AttackLog.event_source.ilike(like_query),
            AttackLog.source_country.ilike(like_query),
            AttackLog.source_ip.ilike(like_query),
            AttackLog.source_activity.ilike(like_query),
        ]

        if query_text.isdigit():
            filters.append(AttackLog.risk_score == int(query_text))

        query = filter_logs_by_source(AttackLog.query, source).filter(or_(*filters))
        remaining_limit = max(limit - len(results), 0)
        logs = (
            query.order_by(AttackLog.timestamp.desc()).limit(remaining_limit).all()
            if remaining_limit
            else []
        )

        for log in logs:
            serialized = serialize_attack_log(log)
            event_source = serialized["event_source"]
            results.append(
                {
                    "type": "Live Incident" if event_source == "live" else "Simulation Incident",
                    "title": serialized["attack_category"],
                    "subtitle": (
                        f"{serialized['attack_label']} | {serialized['risk_level']} | "
                        f"{serialized['country']} | {serialized['risk_score']}/100 | "
                        f"{serialized['timestamp']}"
                    ),
                    "page": "Attack Map" if event_source == "live" else "Simulation",
                    **serialized,
                }
            )

        return jsonify(
            {
                "query": query_text,
                "source": source,
                "count": len(results),
                "results": results,
            }
        )
    @app.route("/download_report")
    @login_required
    def download_report():
        report_path = create_pdf_report("Incident")
        log_report_generation(
            "Incident",
            "download",
            "generated",
            filename=os.path.basename(report_path),
            summary=dashboard_stats_payload("all"),
        )
        log_audit_action(
            "report_downloaded",
            entity_type="report_generation_log",
            details={"report_type": "Incident", "filename": os.path.basename(report_path)},
        )
        return send_file(report_path, as_attachment=True)

    @app.route("/send_weekly_report", methods=["POST"])
    @login_required
    def send_weekly_report():
        return report_email_response("Weekly")

    @app.route("/send_monthly_report", methods=["POST"])
    @login_required
    def send_monthly_report():
        return report_email_response("Monthly")

    @app.route("/send_yearly_report", methods=["POST"])
    @login_required
    def send_yearly_report():
        return report_email_response("Yearly")

    @app.route("/ai_assistant")
    @app.route("/ai_assistant/<path:question>")
    @login_required
    def ai_assistant(question=None):
        question = question or request.args.get("q", "")
        answer = build_assistant_answer(question)

        return jsonify({"question": question, "answer": answer})

    @app.route("/assistant/command", methods=["POST"])
    @login_required
    def assistant_command():
        payload = request.get_json(silent=True) or {}
        question = payload.get("command") or payload.get("question") or ""
        return jsonify({"question": question, "answer": build_assistant_answer(question)})

    @app.route("/device_stats")
    @login_required
    def device_stats():
        cpu_usage = psutil.cpu_percent(interval=0.2)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage(os.path.abspath(os.sep))
        network = psutil.net_io_counters()

        return jsonify(
            {
                "cpu_usage": cpu_usage,
                "memory_usage": memory.percent,
                "disk_usage": disk.percent,
                "bytes_sent": network.bytes_sent,
                "bytes_received": network.bytes_recv,
                "status": "Online",
            }
        )

    @app.route("/<path:asset_path>")
    def desktop_frontend(asset_path):
        if desktop_frontend_enabled():
            return serve_frontend_asset(asset_path)

        return api_error("Not found.", 404)


def register_error_handlers(app):
    @app.errorhandler(HTTPException)
    def handle_http_exception(error):
        return api_error(error.description or error.name, error.code or 500)

    @app.errorhandler(ValueError)
    def handle_value_error(error):
        db.session.rollback()
        return api_error(str(error), 400)

    @app.errorhandler(RuntimeError)
    def handle_runtime_error(error):
        db.session.rollback()
        return api_error(str(error), 500)

    @app.errorhandler(Exception)
    def handle_exception(error):
        db.session.rollback()
        app.logger.exception(error)
        return api_error("Internal server error", 500)


def register_security_headers(app):
    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=()",
        )

        if request.path.startswith(("/auth", "/dashboard_stats", "/attack_history")):
            response.headers.setdefault("Cache-Control", "no-store")

        return response


def weekly_report_job():
    send_email_report(DEFAULT_ANALYST_EMAIL, "Weekly")
    print("Weekly report sent successfully.")


def monthly_report_job():
    today = datetime.now()
    last_day = calendar.monthrange(today.year, today.month)[1]

    if today.day == last_day:
        send_email_report(DEFAULT_ANALYST_EMAIL, "Monthly")
        print("Monthly report sent successfully.")


def yearly_report_job():
    send_email_report(DEFAULT_ANALYST_EMAIL, "Yearly")
    print("Yearly report sent successfully.")


def start_scheduler():
    if os.getenv("EVOGUARD_ENABLE_SCHEDULER", "false").lower() != "true":
        return None

    scheduler = BackgroundScheduler()

    scheduler.add_job(
        weekly_report_job,
        "cron",
        day_of_week="fri",
        hour=17,
        minute=0,
    )

    scheduler.add_job(
        monthly_report_job,
        "cron",
        hour=17,
        minute=10,
    )

    scheduler.add_job(
        yearly_report_job,
        "cron",
        month=12,
        day=31,
        hour=17,
        minute=20,
    )

    scheduler.start()
    return scheduler


app = create_app()
initialize_database(app)


if __name__ == "__main__":
    scheduler = start_scheduler()
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "5000"))

    try:
        if socketio:
            socketio.run(
                app,
                host=host,
                port=port,
                debug=False,
                allow_unsafe_werkzeug=True,
            )
        else:
            app.run(host=host, port=port, debug=False)
    finally:
        if scheduler:
            scheduler.shutdown()
