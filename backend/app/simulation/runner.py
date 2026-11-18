"""Executes synthetic simulation scenarios through the standard ingestion + detection pipeline."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app.core.errors import NotFoundError
from app.detection.engine import run_detection_for_time_range
from app.domain.enums import IngestionSourceKind, SimulationStatus
from app.ingestion.pipeline import ingest_normalized_events
from app.models import SimulationRun
from app.simulation.scenarios import SCENARIOS_BY_ID, generate_scenario_events


def execute_simulation_scenario(
    db: Session,
    scenario_id: str,
    *,
    seed: int | None = None,
    triggered_by: uuid.UUID | None = None,
    reference_time: datetime | None = None,
) -> SimulationRun:
    if scenario_id not in SCENARIOS_BY_ID:
        raise NotFoundError(f"Simulation scenario {scenario_id!r} not found")

    scenario, actual_seed, events = generate_scenario_events(
        scenario_id, seed=seed, reference_time=reference_time
    )

    sim_run = SimulationRun(
        scenario_id=scenario.id,
        status=SimulationStatus.RUNNING.value,
        seed=actual_seed,
        parameters={"scenario_name": scenario.name},
        triggered_by=triggered_by,
        started_at=datetime.now(UTC),
    )
    db.add(sim_run)
    db.flush()

    try:
        ing_result = ingest_normalized_events(
            db,
            events,
            parser_name=f"simulation:{scenario.id}",
            source_kind=IngestionSourceKind.SIMULATION,
            created_by=triggered_by,
            simulation_run_id=sim_run.id,
        )
        alerts_total = 0
        if ing_result.inserted_events:
            timestamps = [e.timestamp for e in ing_result.inserted_events]
            event_types = {e.event_type for e in ing_result.inserted_events}
            det = run_detection_for_time_range(
                db,
                start_time=min(timestamps),
                end_time=max(timestamps),
                event_types=event_types,
            )
            ing_result.batch.alerts_created = det.alerts_created
            ing_result.batch.alerts_updated = det.alerts_updated
            alerts_total = det.alerts_created + det.alerts_updated

        sim_run.events_generated = ing_result.batch.accepted_count
        sim_run.alerts_generated = alerts_total
        sim_run.status = SimulationStatus.COMPLETED.value
        sim_run.completed_at = datetime.now(UTC)
        db.flush()
    except Exception as exc:
        sim_run.status = SimulationStatus.FAILED.value
        sim_run.error = str(exc)[:500]
        sim_run.completed_at = datetime.now(UTC)
        db.flush()
        raise

    return sim_run
