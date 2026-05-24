# Phase 8 - Threat Intelligence and IOC Enrichment

Phase 8 adds a local threat-intelligence layer to EvoGuard.

## What changed

- Added a local IOC database table.
- Added seeded IOC records for lab IPs, countries, and attack categories.
- Every live or simulation event is enriched before it is saved.
- Enrichment can adjust the final risk score based on IOC reputation and repeated source sightings.
- Events are mapped to MITRE ATT&CK techniques.
- The Threat Intel page now reads real backend data instead of static simulation counters.

## New backend fields

Attack records can now store:

- IOC reputation
- IOC confidence
- enriched threat-intel score
- enrichment summary
- MITRE technique
- MITRE tactic
- matched IOC records

## New API endpoints

```text
GET /threat_intel?source=live
GET /ioc_lookup/<indicator>
```

## IOC examples

```text
203.0.113.77 -> Malicious DoS / DDoS source
198.51.100.23 -> Suspicious probe source
198.51.100.44 -> High-risk R2L source
203.0.113.91 -> Critical U2R source
```

## MITRE mappings

```text
DoS / DDoS -> T1498 - Network Denial of Service
Probe / Scan -> T1046 - Network Service Discovery
R2L -> T1110 - Brute Force
U2R -> T1068 - Exploitation for Privilege Escalation
Normal -> Benign baseline telemetry
```

## Why it matters

This makes EvoGuard's AI decisions more explainable. The backend no longer only says "this attack is high risk"; it can explain whether the source matched an IOC, whether the source appeared before, which MITRE technique applies, and why the AI increased or reduced the final risk.
