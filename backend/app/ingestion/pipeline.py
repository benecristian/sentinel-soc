"""Ingestion pipeline: parses, normalizes, deduplicates and persists events."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.core.errors import ValidationFailedError
from app.domain.enums import IngestionSourceKind
from app.domain.events import NormalizedEvent
from app.ingestion.parsers import (
    IgnoredLine,
    JsonEventPayload,
    ParseContext,
    ParseError,
    detect_parser,
    get_parser,
    payload_to_normalized,
    safe_excerpt,
)
from app.models import IngestionBatch, SecurityEvent

MAX_ERROR_SAMPLES = 25


@dataclass(slots=True)
class IngestionResult:
    batch: IngestionBatch
    inserted_events: list[NormalizedEvent] = field(default_factory=list)


def ingest_lines(
    db: Session,
    lines: Sequence[str],
    *,
    parser_name: str = "auto",
    source_kind: IngestionSourceKind = IngestionSourceKind.UPLOAD,
    original_filename: str | None = None,
    created_by: uuid.UUID | None = None,
    simulation_run_id: uuid.UUID | None = None,
    is_synthetic: bool = False,
    max_line_length: int = 8192,
    reference_time: datetime | None = None,
) -> IngestionResult:
    non_empty = [line for line in lines if line.strip() and not line.lstrip().startswith("#")]
    if not non_empty:
        raise ValidationFailedError("No parseable log lines found")

    try:
        parser = detect_parser(non_empty) if parser_name == "auto" else get_parser(parser_name)
    except (ParseError, ValueError) as exc:
        raise ValidationFailedError(str(exc)) from exc

    ctx = ParseContext(
        reference_time=reference_time or datetime.now(UTC),
        is_synthetic=is_synthetic,
    )

    parsed_events: list[NormalizedEvent] = []
    error_samples: list[dict[str, Any]] = []
    rejected_count = 0
    ignored_count = 0

    for line_no, raw_line in enumerate(lines, start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if len(raw_line) > max_line_length:
            rejected_count += 1
            if len(error_samples) < MAX_ERROR_SAMPLES:
                error_samples.append(
                    {
                        "line": line_no,
                        "error": f"Line exceeds maximum length ({max_line_length} chars)",
                        "excerpt": safe_excerpt(raw_line),
                    }
                )
            continue
        try:
            event = parser.parse(raw_line, ctx)
            parsed_events.append(event)
        except IgnoredLine:
            ignored_count += 1
        except ParseError as exc:
            rejected_count += 1
            if len(error_samples) < MAX_ERROR_SAMPLES:
                error_samples.append(
                    {"line": line_no, "error": str(exc), "excerpt": safe_excerpt(raw_line)}
                )

    return _persist_batch(
        db,
        parsed_events=parsed_events,
        parser_name=parser.name,
        source_kind=source_kind,
        original_filename=original_filename,
        created_by=created_by,
        simulation_run_id=simulation_run_id,
        received_count=len(non_empty),
        rejected_count=rejected_count,
        ignored_count=ignored_count,
        error_samples=error_samples,
    )


def ingest_json_payloads(
    db: Session,
    payloads: Sequence[JsonEventPayload],
    *,
    created_by: uuid.UUID | None = None,
    is_synthetic: bool = False,
) -> IngestionResult:
    if not payloads:
        raise ValidationFailedError("Event batch must not be empty")

    ctx = ParseContext(is_synthetic=is_synthetic)
    parsed_events: list[NormalizedEvent] = []
    error_samples: list[dict[str, Any]] = []
    rejected_count = 0

    for idx, payload in enumerate(payloads, start=1):
        raw_fallback = payload.model_dump_json(exclude_none=True)
        try:
            parsed_events.append(
                payload_to_normalized(
                    payload, raw_fallback=raw_fallback, ctx=ctx, log_source="json"
                )
            )
        except ParseError as exc:
            rejected_count += 1
            if len(error_samples) < MAX_ERROR_SAMPLES:
                error_samples.append(
                    {"index": idx, "error": str(exc), "excerpt": safe_excerpt(raw_fallback)}
                )

    return _persist_batch(
        db,
        parsed_events=parsed_events,
        parser_name="json",
        source_kind=IngestionSourceKind.API,
        original_filename=None,
        created_by=created_by,
        simulation_run_id=None,
        received_count=len(payloads),
        rejected_count=rejected_count,
        ignored_count=0,
        error_samples=error_samples,
    )


def ingest_normalized_events(
    db: Session,
    events: Sequence[NormalizedEvent],
    *,
    parser_name: str = "simulator",
    source_kind: IngestionSourceKind = IngestionSourceKind.SIMULATION,
    created_by: uuid.UUID | None = None,
    simulation_run_id: uuid.UUID | None = None,
) -> IngestionResult:
    return _persist_batch(
        db,
        parsed_events=list(events),
        parser_name=parser_name,
        source_kind=source_kind,
        original_filename=None,
        created_by=created_by,
        simulation_run_id=simulation_run_id,
        received_count=len(events),
        rejected_count=0,
        ignored_count=0,
        error_samples=[],
    )


def _persist_batch(
    db: Session,
    *,
    parsed_events: list[NormalizedEvent],
    parser_name: str,
    source_kind: IngestionSourceKind,
    original_filename: str | None,
    created_by: uuid.UUID | None,
    simulation_run_id: uuid.UUID | None,
    received_count: int,
    rejected_count: int,
    ignored_count: int,
    error_samples: list[dict[str, Any]],
) -> IngestionResult:
    started_at = datetime.now(UTC)
    batch = IngestionBatch(
        source_kind=source_kind.value,
        original_filename=original_filename,
        parser=parser_name,
        received_count=received_count,
        rejected_count=rejected_count,
        ignored_count=ignored_count,
        error_samples=error_samples,
        simulation_run_id=simulation_run_id,
        created_by=created_by,
        started_at=started_at,
    )
    db.add(batch)
    db.flush()

    # Deduplicate within the batch first, then against the DB via ON CONFLICT DO NOTHING.
    unique_by_hash: dict[str, NormalizedEvent] = {}
    in_batch_dups = 0
    for ev in parsed_events:
        h = ev.event_hash
        if h in unique_by_hash:
            in_batch_dups += 1
        else:
            unique_by_hash[h] = ev

    inserted_events: list[NormalizedEvent] = []
    db_dups = 0
    if unique_by_hash:
        rows = [
            {
                "id": ev.event_id,
                "ingestion_batch_id": batch.id,
                "timestamp": ev.timestamp,
                "event_type": ev.event_type.value,
                "event_action": ev.event_action,
                "event_outcome": ev.event_outcome.value,
                "severity": ev.severity.value,
                "source_ip": ev.source_ip,
                "destination_ip": ev.destination_ip,
                "source_port": ev.source_port,
                "destination_port": ev.destination_port,
                "protocol": ev.protocol,
                "username": ev.username,
                "hostname": ev.hostname,
                "service": ev.service,
                "log_source": ev.log_source,
                "raw_event": ev.raw_event,
                "normalized_event": ev.to_document(),
                "is_synthetic": ev.is_synthetic,
                "event_hash": ev_hash,
            }
            for ev_hash, ev in unique_by_hash.items()
        ]
        stmt = (
            pg_insert(SecurityEvent)
            .values(rows)
            .on_conflict_do_nothing(index_elements=[SecurityEvent.event_hash])
            .returning(SecurityEvent.event_hash)
        )
        inserted_hashes = set(db.scalars(stmt).all())
        inserted_events = [
            ev for ev_hash, ev in unique_by_hash.items() if ev_hash in inserted_hashes
        ]
        db_dups = len(unique_by_hash) - len(inserted_events)

    batch.accepted_count = len(inserted_events)
    batch.duplicate_count = in_batch_dups + db_dups
    if inserted_events:
        timestamps = [ev.timestamp for ev in inserted_events]
        batch.events_start = min(timestamps)
        batch.events_end = max(timestamps)
    batch.completed_at = datetime.now(UTC)
    db.flush()

    return IngestionResult(batch=batch, inserted_events=inserted_events)
