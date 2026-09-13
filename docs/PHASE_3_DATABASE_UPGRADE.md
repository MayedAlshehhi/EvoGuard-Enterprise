# Phase 3 - Database Upgrade

## Goal

Phase 3 upgrades EvoGuard from a simple prototype database into a stronger SOC-style event data layer.

## Added

- PostgreSQL-ready deployment through Render Blueprint.
- Stable `event_uuid` values for attack records.
- Normalized `attack_type` values: `dos`, `probe`, `r2l`, `u2r`, and `normal`.
- Event status tracking through `event_status`.
- Raw event payload storage for live intake and simulation evidence.
- User ownership field on attack records.
- Database indexes for faster dashboard, search, and history queries.
- Audit logging for login, logout, live intake, simulation, report generation, and history reset actions.
- Report generation history table.
- Paginated and filterable `/attack_history` response.
- Database summary endpoint at `/database/summary`.

## Main Backend Tables

- `attack_log`: core incident and event history.
- `ai_response_log`: autonomous AI response actions connected to attacks.
- `evoguard_user`: authenticated operator accounts.
- `threat_intel_ioc`: IOC and reputation records.
- `system_audit_log`: security-relevant system actions.
- `report_generation_log`: generated or emailed report records.

## Attack History Filters

`/attack_history` now supports:

- `source=live|simulation|all`
- `attack_type=dos|probe|r2l|u2r|normal`
- `risk_level=Critical|High|Medium|Low`
- `country=Russia`
- `source_ip=203.0.113.77`
- `from=2026-06-01`
- `to=2026-06-01`
- `q=credential`
- `page=1`
- `limit=50`
- `sort=timestamp_desc|timestamp_asc|risk_desc|risk_asc`

## Deployment Note

Local development can continue using SQLite:

```env
EVOGUARD_DATABASE_URL=sqlite:///evoguard.db
```

Production should use PostgreSQL:

```env
EVOGUARD_DATABASE_URL=postgresql://USER:PASSWORD@HOST:5432/DATABASE
```

The included `render.yaml` now provisions a Render PostgreSQL database and connects the backend to it automatically.
