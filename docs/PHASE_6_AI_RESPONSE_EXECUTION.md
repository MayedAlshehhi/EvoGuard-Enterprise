# Phase 6 - AI Response Execution

Phase 6 turns EvoGuard from a detection dashboard into an autonomous AI response prototype.

## What Changed

- Every attack now generates AI response execution records.
- The backend stores those records in `AIResponseLog`.
- The Dashboard shows an AI Response Execution Center.
- Attack Map route details show containment status and executed AI actions.
- The AI response story no longer depends on a SOC analyst taking final action.
- The backend exposes autonomous playbooks for each attack family.
- Each AI action now includes playbook name, automation level, decision text, outcome text, execution stage, status, and confidence.
- Response summaries now include total actions, executed actions, monitoring actions, pending actions, execution rate, automation mode, containment status, and average confidence.

## Backend Endpoints

Read recent AI response actions:

```txt
GET http://127.0.0.1:5000/ai_responses?source=live
```

Read response actions for one attack:

```txt
GET http://127.0.0.1:5000/ai_responses?source=live&attack_id=1
```

Read AI response summary:

```txt
GET http://127.0.0.1:5000/ai_response_summary?source=live
```

Read the AI response playbook library:

```txt
GET http://127.0.0.1:5000/ai_response_playbook
```

Read the full autonomous response plan for one attack:

```txt
GET http://127.0.0.1:5000/autonomous_response_plan/1
```

## AI Response States

- Detected
- Analyzed
- Mitigation Planned
- Action Executed
- Contained
- Monitoring

## AI Playbooks

- DoS / DDoS: Availability Protection Playbook.
- Probe / Scan: Reconnaissance Suppression Playbook.
- R2L: Identity Containment Playbook.
- U2R: Privilege Escalation Containment Playbook.
- Normal: Benign Telemetry Baseline Playbook.

## What The AI Does

For every received or simulated event, EvoGuard:

1. Classifies the attack.
2. Calculates risk.
3. Enriches with IOC and MITRE context.
4. Selects the matching autonomous response playbook.
5. Generates simulated defense actions.
6. Marks the actions as executed or monitoring based on risk.
7. Stores all response actions in the database.
8. Broadcasts response updates to the dashboard in realtime.

## Demo Story

EvoGuard receives a cyber event, classifies it, calculates risk, decides the autonomous response, executes simulated defense actions, records every action, updates the dashboard, and continues monitoring.

## Important Note

These are simulated execution actions for a senior project prototype. They model what an autonomous cyber defense platform would do, without changing real firewall, endpoint, or identity systems.
