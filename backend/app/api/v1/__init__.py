"""Version 1 API router aggregation."""

from fastapi import APIRouter

from app.api.v1.alerts import alerts_router
from app.api.v1.core import auth_router, health_router, users_router
from app.api.v1.detections import detections_router
from app.api.v1.events import events_router, ingestion_router
from app.api.v1.incidents import incidents_router
from app.api.v1.operations import (
    dashboard_router,
    hunting_router,
    mitre_router,
    reports_router,
    simulations_router,
    system_router,
)

api_router = APIRouter()
api_router.include_router(health_router)
api_router.include_router(auth_router)
api_router.include_router(users_router)
api_router.include_router(dashboard_router)
api_router.include_router(events_router)
api_router.include_router(ingestion_router)
api_router.include_router(detections_router)
api_router.include_router(alerts_router)
api_router.include_router(incidents_router)
api_router.include_router(mitre_router)
api_router.include_router(hunting_router)
api_router.include_router(simulations_router)
api_router.include_router(reports_router)
api_router.include_router(system_router)
