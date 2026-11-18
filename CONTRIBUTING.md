# Contributing to SENTINEL SOC

Thank you for your interest in contributing to **SENTINEL SOC**.

## Engineering Principles

1. **Pure Detection Core:** Parsers (`app/ingestion/parsers/`) and detection rules (`app/detection/rules/`) must remain pure Python functions operating on `NormalizedEvent` objects with zero FastAPI or SQLAlchemy imports.
2. **Test Every Rule & Parser:** Every new detection rule must include unit tests covering:
   - True positive scenario
   - Benign scenario (must not alert)
   - Below-threshold boundary
   - Exact time-window boundary (`<= time_window_seconds` vs `> time_window_seconds`)
   - CIDR allowlist suppression
   - Disabled rule check
   - Benign baseline regression check (`normal_activity` scenario must produce 0 findings)
3. **Never Use SQLite for Database Tests:** Integration and API tests run against real PostgreSQL 16 (`INET`, `JSONB`, partial unique indexes, `ON CONFLICT DO NOTHING`).
4. **Defensive Input Handling:** Treat all log lines and event fields as untrusted attacker-controlled input. Never interpolate user filters into raw SQL, never execute uploaded content, and never render raw HTML from log strings.

## Quality Checks Before Submitting a Pull Request

### Backend
```bash
cd backend
ruff check app tests
ruff format --check app tests
mypy app
pytest -v
```

### Frontend
```bash
cd frontend
npm run typecheck
npm test
npm run build
```
