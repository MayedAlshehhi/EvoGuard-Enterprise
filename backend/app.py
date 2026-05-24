import calendar
import csv
import io
import json
import os
import random
import smtplib
import sys
from datetime import datetime, timedelta
from email.message import EmailMessage

import joblib
import pandas as pd
import psutil
from apscheduler.schedulers.background import BackgroundScheduler
from flask import Flask, jsonify, request, send_file, session
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from sqlalchemy import or_, text
from werkzeug.security import check_password_hash, generate_password_hash

try:
    from flask_socketio import SocketIO, emit
except ImportError:
    SocketIO = None
    emit = None


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.abspath(os.path.join(BASE_DIR, ".."))
AI_ENGINE_DIR = os.path.join(PROJECT_DIR, "ai_engine")
REPORT_DIR = os.path.join(BASE_DIR, "reports")

sys.path.insert(0, AI_ENGINE_DIR)

from agentic_ai import agentic_analysis


MODEL_PATH = os.path.join(AI_ENGINE_DIR, "evoguard_optimized_model.pkl")
ENCODER_PATH = os.path.join(AI_ENGINE_DIR, "label_encoders.pkl")
FEATURE_PATH = os.path.join(AI_ENGINE_DIR, "selected_features.pkl")
METRICS_PATH = os.path.join(AI_ENGINE_DIR, "model_metrics.json")

AVAILABLE_ATTACK_TYPES = ["dos", "probe", "r2l", "u2r", "normal"]
DEFAULT_ANALYST_EMAIL = os.getenv("EVOGUARD_ANALYST_EMAIL", "evoguardzu@gmail.com")
DEFAULT_ADMIN_USERNAME = os.getenv("EVOGUARD_DEFAULT_USERNAME", "mayed")
DEFAULT_ADMIN_PASSWORD = os.getenv("EVOGUARD_DEFAULT_PASSWORD", "mayed123")
DEFAULT_CORS_ORIGINS = ["http://localhost:3000", "http://127.0.0.1:3000"]

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


class AttackLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    attack_label = db.Column(db.String(100))
    attack_category = db.Column(db.String(100))
    risk_score = db.Column(db.Integer)
    risk_level = db.Column(db.String(50))
    explanation = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    event_source = db.Column(db.String(50), default="simulation", nullable=False)
    source_country = db.Column(db.String(100))
    source_ip = db.Column(db.String(64))
    source_activity = db.Column(db.String(120))
    response_mode = db.Column(db.String(120))
    response_confidence = db.Column(db.Float)
    intel_reputation = db.Column(db.String(80))
    intel_confidence = db.Column(db.Float)
    intel_score = db.Column(db.Integer)
    intel_summary = db.Column(db.Text)
    mitre_technique = db.Column(db.String(160))
    mitre_tactic = db.Column(db.String(100))
    ioc_matches = db.Column(db.Text)


class AIResponseLog(db.Model):
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
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(80), default="AI Defense Operator")
    access_level = db.Column(db.String(80), default="Administrator")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)


class ThreatIntelIOC(db.Model):
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


def create_app():
    app = Flask(__name__)
    app.secret_key = os.getenv("EVOGUARD_SECRET_KEY", "evoguard-dev-secret-change-me")
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
    )

    cors_origins = configured_cors_origins()
    CORS(app, resources={r"/*": {"origins": cors_origins}}, supports_credentials=True)

    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
        "EVOGUARD_DATABASE_URL", "sqlite:///evoguard.db"
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    db.init_app(app)

    if socketio:
        socketio.init_app(app, cors_allowed_origins=cors_origins)

    register_routes(app)
    register_error_handlers(app)
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


def serialize_user(user):
    if not user:
        return None

    return {
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "access_level": user.access_level,
        "last_login": user.last_login.strftime("%Y-%m-%d %H:%M:%S")
        if user.last_login
        else None,
    }


def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    return User.query.get(user_id)


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

    action_map = {
        "dos": [
            ("Block attacking source", "firewall_block", "Block high-volume traffic from the malicious source IP."),
            ("Apply adaptive rate limit", "rate_limit", "Reduce request pressure on protected services."),
            ("Activate DDoS shield", "traffic_scrubbing", "Route suspicious flow patterns through mitigation controls."),
            ("Monitor service availability", "availability_monitor", "Continue watching latency and service stability."),
        ],
        "probe": [
            ("Throttle scanner traffic", "traffic_throttle", "Slow reconnaissance activity while preserving service availability."),
            ("Deploy scan detection rule", "ids_rule", "Create a temporary detection rule for repeated probe behavior."),
            ("Harden exposed services", "surface_reduction", "Increase monitoring around scanned ports and exposed services."),
            ("Add source to AI watchlist", "watchlist", "Track recurring behavior from the same source."),
        ],
        "r2l": [
            ("Block suspicious remote session", "session_block", "Terminate unauthorized remote access behavior."),
            ("Trigger adaptive authentication", "identity_control", "Increase identity challenge level for targeted accounts."),
            ("Lock targeted account window", "account_lock", "Temporarily restrict accounts showing compromise indicators."),
            ("Monitor credential replay", "identity_monitor", "Watch for repeated authentication attempts."),
        ],
        "u2r": [
            ("Isolate suspicious endpoint", "endpoint_isolation", "Contain host activity that suggests privilege escalation."),
            ("Terminate elevated process", "process_control", "Stop suspicious elevated execution attempts."),
            ("Revoke risky privilege path", "privilege_control", "Restrict the privilege path used by the attacker."),
            ("Capture forensic snapshot", "forensics", "Preserve system evidence for later investigation."),
        ],
        "normal": [
            ("Store baseline telemetry", "baseline_learning", "Save event shape as normal behavior for future comparison."),
            ("Continue passive monitoring", "passive_monitor", "No defensive disruption required for benign traffic."),
        ],
    }

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
    actions = action_map.get(category, action_map["normal"])

    return [
        {
            "action_name": action_name,
            "action_type": action_type,
            "execution_stage": stages[min(index, len(stages) - 1)],
            "status": status,
            "confidence": round(max(50, min(99, base_confidence - (index * 2.5))), 2),
            "explanation": f"{explanation} Target source: {source_ip}.",
        }
        for index, (action_name, action_type, explanation) in enumerate(actions)
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


def serialize_ai_response_log(response_log):
    attack = AttackLog.query.get(response_log.attack_id)

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
            "containment_status": "Pending",
            "average_confidence": None,
        }

    executed_actions = sum(1 for item in response_logs if item.status == "Executed")
    monitoring_actions = sum(1 for item in response_logs if item.status == "Monitoring")
    average_confidence = round(
        sum(item.confidence or 0 for item in response_logs) / len(response_logs),
        2,
    )

    return {
        "total_actions": len(response_logs),
        "executed_actions": executed_actions,
        "monitoring_actions": monitoring_actions,
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
        },
    )
    socketio.emit(
        "evoguard:ai_response",
        {
            "source": source,
            "attack_id": attack_log.id,
            "responses": serialized_responses,
            "summary": summary,
        },
    )
    socketio.emit("evoguard:stats_updated", stats)


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
        "realtime": realtime_enabled(),
    }


def register_socket_handlers():
    global socket_handlers_registered

    if not socketio or socket_handlers_registered:
        return

    socket_handlers_registered = True

    @socketio.on("connect")
    def handle_socket_connect():
        emit("evoguard:connected", socket_sync_payload("live"))

    @socketio.on("evoguard:request_sync")
    def handle_socket_sync(payload=None):
        requested = (payload or {}).get("source", "live")
        emit("evoguard:connected", socket_sync_payload(requested))


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


def build_live_test_payload(event_type="random"):
    if event_type == "random":
        event_type = random.choice(list(LIVE_TEST_EVENT_LIBRARY.keys()))

    if event_type not in LIVE_TEST_EVENT_LIBRARY:
        raise ValueError(f"Unsupported live test event type: {event_type}")

    payload = random.choice(LIVE_TEST_EVENT_LIBRARY[event_type]).copy()
    payload["attack_type"] = event_type
    payload["ip"] = random_public_test_ip()
    return payload


def normalize_bulk_event(raw_event):
    event = raw_event or {}
    return {
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
    }


def parse_csv_events(csv_text):
    reader = csv.DictReader(io.StringIO(csv_text))
    return [normalize_bulk_event(row) for row in reader]


def create_live_attack_log(payload):
    payload = payload or {}
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

    new_log = AttackLog(
        attack_label=analysis["attack_label"],
        attack_category=analysis["attack_category"],
        risk_score=analysis["risk_score"],
        risk_level=analysis["risk_level"],
        explanation=analysis["explanation"],
        event_source="live",
        source_country=source_context["source_country"],
        source_ip=source_context["source_ip"],
        source_activity=source_context["source_activity"],
        response_mode=analysis["response_mode"],
        response_confidence=analysis["response_confidence"],
    )
    apply_intel_to_log(new_log, threat_intel)

    db.session.add(new_log)
    db.session.commit()
    create_ai_response_logs(new_log, analysis)
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

    new_log = AttackLog(
        attack_label=analysis["attack_label"],
        attack_category=analysis["attack_category"],
        risk_score=analysis["risk_score"],
        risk_level=analysis["risk_level"],
        explanation=analysis["explanation"],
        event_source="simulation",
        source_country=source_context["source_country"],
        source_ip=source_context["source_ip"],
        source_activity=source_context["source_activity"],
        response_mode=analysis["response_mode"],
        response_confidence=analysis["response_confidence"],
    )
    apply_intel_to_log(new_log, threat_intel)

    db.session.add(new_log)
    db.session.commit()
    create_ai_response_logs(new_log, analysis)
    broadcast_realtime_update(new_log)

    return {
        **analysis,
        **source_context,
        "id": new_log.id,
        "event_source": "simulation",
        "attack_type": attack_type,
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
    sender_email = os.getenv("EVOGUARD_EMAIL")
    app_password = os.getenv("EVOGUARD_EMAIL_PASSWORD")

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


def parse_reset_confirmation():
    payload = request.get_json(silent=True) or {}
    return (
        request.args.get("confirm")
        or payload.get("confirm")
        or request.form.get("confirm")
        or ""
    )



def ensure_attacklog_schema():
    columns = {
        row[1]
        for row in db.session.execute(text("PRAGMA table_info(attack_log)")).fetchall()
    }

    migrations = {
        "event_source": "ALTER TABLE attack_log ADD COLUMN event_source VARCHAR(50) DEFAULT 'simulation'",
        "source_country": "ALTER TABLE attack_log ADD COLUMN source_country VARCHAR(100)",
        "source_ip": "ALTER TABLE attack_log ADD COLUMN source_ip VARCHAR(64)",
        "source_activity": "ALTER TABLE attack_log ADD COLUMN source_activity VARCHAR(120)",
        "response_mode": "ALTER TABLE attack_log ADD COLUMN response_mode VARCHAR(120)",
        "response_confidence": "ALTER TABLE attack_log ADD COLUMN response_confidence FLOAT",
        "intel_reputation": "ALTER TABLE attack_log ADD COLUMN intel_reputation VARCHAR(80)",
        "intel_confidence": "ALTER TABLE attack_log ADD COLUMN intel_confidence FLOAT",
        "intel_score": "ALTER TABLE attack_log ADD COLUMN intel_score INTEGER",
        "intel_summary": "ALTER TABLE attack_log ADD COLUMN intel_summary TEXT",
        "mitre_technique": "ALTER TABLE attack_log ADD COLUMN mitre_technique VARCHAR(160)",
        "mitre_tactic": "ALTER TABLE attack_log ADD COLUMN mitre_tactic VARCHAR(100)",
        "ioc_matches": "ALTER TABLE attack_log ADD COLUMN ioc_matches TEXT",
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
    if User.query.filter_by(username=DEFAULT_ADMIN_USERNAME).first():
        return

    db.session.add(
        User(
            username=DEFAULT_ADMIN_USERNAME,
            password_hash=generate_password_hash(DEFAULT_ADMIN_PASSWORD),
            role="AI Defense Operator",
            access_level="Administrator",
        )
    )
    db.session.commit()


def requested_source(default="all"):
    source = (request.args.get("source") or default or "all").lower()
    return source if source in ["all", "live", "simulation"] else "all"


def filter_logs_by_source(query, source=None):
    selected_source = source or requested_source()

    if selected_source in ["live", "simulation"]:
        return query.filter(AttackLog.event_source == selected_source)

    return query


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
        "attack_label": log.attack_label,
        "attack_category": log.attack_category,
        "risk_score": log.risk_score,
        "risk_level": log.risk_level,
        "explanation": log.explanation,
        "timestamp": log.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "event_source": log.event_source or "simulation",
        "country": country,
        "source_country": country,
        "ip": ip,
        "source_ip": ip,
        "source_activity": activity,
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


def register_routes(app):
    @app.route("/")
    def home():
        return jsonify(
            {
                "system": "EvoGuard Enterprise",
                "status": "Backend API is running",
                "available_attacks": AVAILABLE_ATTACK_TYPES,
            }
        )

    @app.route("/auth/session")
    def auth_session():
        user = current_user()
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

        user.last_login = datetime.utcnow()
        db.session.commit()
        session["user_id"] = user.id

        return jsonify(
            {
                "authenticated": True,
                "user": serialize_user(user),
            }
        )

    @app.route("/auth/logout", methods=["POST"])
    def auth_logout():
        session.clear()
        return jsonify({"authenticated": False, "status": "logged_out"})

    @app.route("/dashboard_stats")
    def dashboard_stats():
        source = requested_source("all")
        return jsonify(dashboard_stats_payload(source))

    @app.route("/realtime_status")
    def realtime_status():
        return jsonify(
            {
                "enabled": realtime_enabled(),
                "transport": "socket.io" if realtime_enabled() else "polling",
                "events": [
                    "evoguard:connected",
                    "evoguard:new_attack",
                    "evoguard:ai_response",
                    "evoguard:stats_updated",
                ],
            }
        )

    @app.route("/ai_defense_score")
    def ai_defense_score():
        source = requested_source("all")
        logs = filter_logs_by_source(
            AttackLog.query.order_by(AttackLog.timestamp.desc()),
            source,
        ).all()
        return jsonify(calculate_ai_defense_score(logs))

    @app.route("/ai_responses")
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
    def ai_response_summary():
        source = requested_source("all")
        logs = filter_logs_by_source(
            AttackLog.query.order_by(AttackLog.timestamp.desc()),
            source,
        ).all()
        return jsonify(response_summary_for_logs(logs))

    @app.route("/threat_intel")
    def threat_intel():
        source = requested_source("live")
        return jsonify(threat_intel_payload(source))

    @app.route("/ioc_lookup/<path:indicator>")
    def ioc_lookup(indicator):
        normalized_indicator = indicator.strip()
        like_indicator = normalized_indicator.lower()
        iocs = [
            ioc
            for ioc in ThreatIntelIOC.query.all()
            if str(ioc.indicator_value or "").lower() == like_indicator
        ]
        logs = (
            AttackLog.query.filter(
                or_(
                    AttackLog.source_ip == normalized_indicator,
                    AttackLog.source_country.ilike(normalized_indicator),
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
                "verdict": (
                    iocs[0].reputation
                    if iocs
                    else "Observed" if logs else "Unknown"
                ),
            }
        )

    @app.route("/model_metrics")
    def model_metrics():
        return jsonify(load_model_metrics())

    @app.route("/simulate_attack")
    def simulate_attack_default():
        return simulate_attack_by_type("dos")

    @app.route("/simulate_attack/<attack_type>")
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
    def ingest_event():
        payload = request.get_json(silent=True) or {}
        return jsonify(create_live_attack_log(payload)), 201

    @app.route("/bulk_ingest_events", methods=["POST"])
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
                ],
            }
        ), 201

    @app.route("/live_event_examples")
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
                "examples": examples,
                "powershell_example": (
                    "Invoke-RestMethod -Method POST -Uri http://127.0.0.1:5000/ingest_event "
                    "-ContentType 'application/json' "
                    "-Body '{\"attack_type\":\"dos\",\"country\":\"Russia\","
                    "\"ip\":\"203.0.113.77\","
                    "\"source_activity\":\"High-volume TCP flood\"}'"
                ),
                "python_tool_example": "python backend/tools/send_live_event.py --type dos --count 1",
                "csv_tool_example": "python backend/tools/send_csv_events.py data/sample_live_events.csv",
            }
        )

    @app.route("/test_live_event", defaults={"event_type": "random"}, methods=["GET", "POST"])
    @app.route("/test_live_event/<event_type>", methods=["GET", "POST"])
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
    def attack_history():
        limit = min(request.args.get("limit", default=50, type=int), 200)
        source = requested_source("all")
        logs = (
            filter_logs_by_source(
                AttackLog.query.order_by(AttackLog.timestamp.desc()),
                source,
            )
            .limit(limit)
            .all()
        )

        return jsonify([serialize_attack_log(log) for log in logs])
    @app.route("/reset_attack_history", methods=["GET", "POST", "DELETE"])
    @app.route("/clear_attack_history", methods=["GET", "POST", "DELETE"])
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
    def download_report():
        report_path = create_pdf_report("Incident")
        return send_file(report_path, as_attachment=True)

    @app.route("/send_weekly_report", methods=["GET", "POST"])
    def send_weekly_report():
        send_email_report(DEFAULT_ANALYST_EMAIL, "Weekly")
        return jsonify({"status": "Weekly report sent successfully"})

    @app.route("/send_monthly_report", methods=["GET", "POST"])
    def send_monthly_report():
        send_email_report(DEFAULT_ANALYST_EMAIL, "Monthly")
        return jsonify({"status": "Monthly report sent successfully"})

    @app.route("/send_yearly_report", methods=["GET", "POST"])
    def send_yearly_report():
        send_email_report(DEFAULT_ANALYST_EMAIL, "Yearly")
        return jsonify({"status": "Yearly report sent successfully"})

    @app.route("/ai_assistant")
    @app.route("/ai_assistant/<path:question>")
    def ai_assistant(question=None):
        question = question or request.args.get("q", "")
        answer = build_assistant_answer(question)

        return jsonify({"question": question, "answer": answer})

    @app.route("/assistant/command", methods=["POST"])
    def assistant_command():
        payload = request.get_json(silent=True) or {}
        question = payload.get("command") or payload.get("question") or ""
        return jsonify({"question": question, "answer": build_assistant_answer(question)})

    @app.route("/device_stats")
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


def register_error_handlers(app):
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


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        ensure_attacklog_schema()
        seed_default_user()
        seed_threat_intel_iocs()

    scheduler = start_scheduler()

    try:
        if socketio:
            socketio.run(app, debug=False, allow_unsafe_werkzeug=True)
        else:
            app.run(debug=False)
    finally:
        if scheduler:
            scheduler.shutdown()


