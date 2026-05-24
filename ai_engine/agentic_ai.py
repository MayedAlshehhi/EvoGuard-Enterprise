from attack_mapper import map_attack_category


AUTONOMOUS_ACTIONS = {
    "Normal": [
        "EvoGuard AI continues passive monitoring.",
        "Store the traffic pattern as baseline telemetry.",
        "No defensive containment is required.",
    ],
    "DoS / DDoS": [
        "EvoGuard AI rate-limits suspicious high-volume traffic.",
        "Block attacking source IP addresses at the firewall layer.",
        "Activate DDoS mitigation rules for protected services.",
        "Increase availability monitoring for the targeted asset.",
    ],
    "Probe / Scanning": [
        "EvoGuard AI adds the source to the watchlist.",
        "Increase logging on scanned services and exposed ports.",
        "Throttle repeated reconnaissance requests.",
        "Correlate the source with recent intrusion attempts.",
    ],
    "R2L / Unauthorized Access": [
        "EvoGuard AI blocks the suspicious remote source.",
        "Review authentication telemetry for the targeted account.",
        "Force credential rotation for affected identities.",
        "Restrict suspicious remote sessions until verified safe.",
    ],
    "U2R / Privilege Escalation": [
        "EvoGuard AI isolates the affected endpoint.",
        "Terminate suspicious elevated processes.",
        "Preserve privilege escalation evidence for reporting.",
        "Lock down administrator-level activity until containment completes.",
    ],
    "Unknown Attack": [
        "EvoGuard AI flags the event for enhanced monitoring.",
        "Collect additional telemetry from the affected services.",
        "Apply conservative containment until classification improves.",
    ],
}


EXPLANATIONS = {
    "Normal": "The traffic pattern appears normal and does not show clear malicious behavior.",
    "DoS / DDoS": "The system detected traffic patterns commonly linked to service disruption or flooding attacks.",
    "Probe / Scanning": "The system detected scanning behavior that may indicate reconnaissance before an attack.",
    "R2L / Unauthorized Access": "The system detected suspicious behavior that may indicate unauthorized remote access attempts.",
    "U2R / Privilege Escalation": "The system detected behavior that may indicate attempts to gain higher system privileges.",
    "Unknown Attack": "The system detected suspicious behavior that does not clearly match a known category.",
}


def calculate_risk_score(attack_label):
    category = map_attack_category(attack_label)

    if category == "Normal":
        return 5, "Low"

    if category == "DoS / DDoS":
        return 85, "High"

    if category == "Probe / Scanning":
        return 65, "Medium"

    if category == "R2L / Unauthorized Access":
        return 90, "Critical"

    if category == "U2R / Privilege Escalation":
        return 95, "Critical"

    return 50, "Medium"


def generate_explanation(attack_label):
    category = map_attack_category(attack_label)
    return EXPLANATIONS.get(category, EXPLANATIONS["Unknown Attack"])


def recommend_action(attack_label):
    category = map_attack_category(attack_label)
    return AUTONOMOUS_ACTIONS.get(category, AUTONOMOUS_ACTIONS["Unknown Attack"])


def calculate_response_confidence(risk_score, actions):
    action_count = len(actions or [])

    if risk_score >= 85:
        expected_actions = 4
    elif risk_score >= 60:
        expected_actions = 3
    else:
        expected_actions = 2

    action_coverage = min(100, (action_count / expected_actions) * 100)
    risk_confidence = min(100, max(0, risk_score))

    return round((risk_confidence * 0.55) + (action_coverage * 0.45), 2)


def agentic_analysis(attack_label):
    category = map_attack_category(attack_label)
    risk_score, risk_level = calculate_risk_score(attack_label)
    explanation = generate_explanation(attack_label)
    actions = recommend_action(attack_label)

    return {
        "attack_label": attack_label,
        "attack_category": category,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "explanation": explanation,
        "recommended_actions": actions,
        "response_mode": "Autonomous AI response simulation",
        "response_confidence": calculate_response_confidence(risk_score, actions),
    }