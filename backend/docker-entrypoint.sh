#!/bin/sh
set -eu

echo "[sentinel-soc] Running database migrations..."
alembic upgrade head

echo "[sentinel-soc] Seeding MITRE ATT&CK catalog and default detection rules..."
python -m app.cli seed-reference

if [ -n "${SENTINEL_ADMIN_PASSWORD:-}" ]; then
    echo "[sentinel-soc] Ensuring initial admin and analyst accounts exist..."
    SENTINEL_USER_PASSWORD="${SENTINEL_ADMIN_PASSWORD}" \
        python -m app.cli create-user \
            --username "${SENTINEL_ADMIN_USERNAME:-admin}" \
            --role admin \
            --display-name "SOC Administrator" \
            --if-not-exists
    SENTINEL_USER_PASSWORD="${SENTINEL_ADMIN_PASSWORD}" \
        python -m app.cli create-user \
            --username "analyst" \
            --role analyst \
            --display-name "SOC Tier-2 Analyst" \
            --if-not-exists
fi

if [ "${SEED_DEMO_ON_STARTUP:-true}" = "true" ]; then
    echo "[sentinel-soc] Seeding synthetic demonstration scenarios..."
    python -m app.cli seed-demo
fi

echo "[sentinel-soc] Starting FastAPI server on :8000..."
exec uvicorn app.main:create_app --factory --host 0.0.0.0 --port 8000 --no-server-header
