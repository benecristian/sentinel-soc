"""Event Explorer, JSON Ingestion and Log File Upload endpoints."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, Query, Request, UploadFile, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import (
    AnalystUser,
    ViewerUser,
    get_client_ip,
    get_db,
    get_settings_dep,
    rate_limit,
)
from app.core.config import Settings
from app.core.errors import NotFoundError, PayloadTooLargeError, ValidationFailedError
from app.detection.engine import run_detection_for_time_range
from app.domain.enums import EventOutcome, EventType, IngestionSourceKind, Severity
from app.hunting.queries import EventFilterParams, query_events_page
from app.ingestion.parsers import SUPPORTED_FORMATS
from app.ingestion.pipeline import ingest_json_payloads, ingest_lines
from app.ingestion.upload import read_validated_upload
from app.models import IngestionBatch, SecurityEvent, User
from app.schemas.common import MAX_PAGE_SIZE, Page
from app.schemas.soc import IngestBatchRequest, IngestionBatchRead, SecurityEventRead
from app.services.audit import record_audit

events_router = APIRouter(prefix="/events", tags=["events"])
ingestion_router = APIRouter(prefix="/ingestion", tags=["ingestion"])


@events_router.get("", response_model=Page[SecurityEventRead])
def list_events(
    db: Session = Depends(get_db),
    _: User = ViewerUser,
    ip: str | None = Query(default=None),
    source_ip: str | None = Query(default=None),
    destination_ip: str | None = Query(default=None),
    cidr: str | None = Query(default=None),
    username: str | None = Query(default=None),
    hostname: str | None = Query(default=None),
    event_type: EventType | None = Query(default=None),
    event_outcome: EventOutcome | None = Query(default=None),
    severity: Severity | None = Query(default=None),
    log_source: str | None = Query(default=None),
    is_synthetic: bool | None = Query(default=None),
    start_time: datetime | None = Query(default=None, alias="from"),
    end_time: datetime | None = Query(default=None, alias="to"),
    q: str | None = Query(default=None, max_length=256),
    field_key: str | None = Query(default=None),
    field_value: str | None = Query(default=None, max_length=256),
    limit: int = Query(default=50, ge=1, le=MAX_PAGE_SIZE),
    offset: int = Query(default=0, ge=0, le=1_000_000),
) -> Page[SecurityEventRead]:
    params = EventFilterParams(
        ip=ip,
        source_ip=source_ip,
        destination_ip=destination_ip,
        cidr=cidr,
        username=username,
        hostname=hostname,
        event_type=event_type,
        event_outcome=event_outcome,
        severity=severity,
        log_source=log_source,
        is_synthetic=is_synthetic,
        start_time=start_time,
        end_time=end_time,
        q=q,
        field_key=field_key,
        field_value=field_value,
    )
    items, total = query_events_page(db, params, limit=limit, offset=offset)
    return Page(
        items=[SecurityEventRead.model_validate(item) for item in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@events_router.get("/{event_id}", response_model=SecurityEventRead)
def get_event(
    event_id: uuid.UUID,
    db: Session = Depends(get_db),
    _: User = ViewerUser,
) -> SecurityEventRead:
    event = db.get(SecurityEvent, event_id)
    if event is None:
        raise NotFoundError("Security event not found")
    return SecurityEventRead.model_validate(event)


@events_router.post(
    "/ingest",
    response_model=IngestionBatchRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(rate_limit("ingest", "ingest_rate_limit_per_minute"))],
)
def ingest_events_endpoint(
    body: IngestBatchRequest,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
    user: User = AnalystUser,
) -> IngestionBatch:
    if len(body.events) > settings.max_ingest_batch:
        raise PayloadTooLargeError(f"Batch exceeds maximum of {settings.max_ingest_batch} events")

    result = ingest_json_payloads(db, body.events, created_by=user.id)
    if result.inserted_events:
        timestamps = [e.timestamp for e in result.inserted_events]
        types = {e.event_type for e in result.inserted_events}
        det = run_detection_for_time_range(
            db, start_time=min(timestamps), end_time=max(timestamps), event_types=types
        )
        result.batch.alerts_created = det.alerts_created
        result.batch.alerts_updated = det.alerts_updated

    record_audit(
        db,
        action="events.ingested",
        actor_id=user.id,
        target_type="ingestion_batch",
        target_id=result.batch.id,
        changes={
            "received": result.batch.received_count,
            "accepted": result.batch.accepted_count,
            "alerts_created": result.batch.alerts_created,
        },
        client_ip=get_client_ip(request),
    )
    db.commit()
    db.refresh(result.batch)
    return result.batch


@events_router.post(
    "/upload",
    response_model=IngestionBatchRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(rate_limit("upload", "upload_rate_limit_per_minute"))],
)
async def upload_log_file(
    request: Request,
    file: Annotated[UploadFile, File(...)],
    log_format: Annotated[str, Form(alias="format")] = "auto",
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
    user: User = AnalystUser,
) -> IngestionBatch:
    fmt = log_format.strip().lower()
    if fmt not in SUPPORTED_FORMATS:
        raise ValidationFailedError(
            f"Unsupported format {fmt!r}. Supported: {', '.join(SUPPORTED_FORMATS)}"
        )

    validated = await read_validated_upload(file, settings)
    effective_format = (
        "json" if (fmt == "auto" and validated.extension in (".json", ".jsonl")) else fmt
    )

    result = ingest_lines(
        db,
        validated.lines,
        parser_name=effective_format,
        source_kind=IngestionSourceKind.UPLOAD,
        original_filename=validated.sanitized_filename,
        created_by=user.id,
        max_line_length=settings.max_line_length,
    )
    if result.inserted_events:
        timestamps = [e.timestamp for e in result.inserted_events]
        types = {e.event_type for e in result.inserted_events}
        det = run_detection_for_time_range(
            db, start_time=min(timestamps), end_time=max(timestamps), event_types=types
        )
        result.batch.alerts_created = det.alerts_created
        result.batch.alerts_updated = det.alerts_updated

    record_audit(
        db,
        action="events.uploaded",
        actor_id=user.id,
        target_type="ingestion_batch",
        target_id=result.batch.id,
        changes={
            "filename": validated.sanitized_filename,
            "parser": result.batch.parser,
            "accepted": result.batch.accepted_count,
            "rejected": result.batch.rejected_count,
        },
        client_ip=get_client_ip(request),
    )
    db.commit()
    db.refresh(result.batch)
    return result.batch


@ingestion_router.get("/batches", response_model=Page[IngestionBatchRead])
def list_ingestion_batches(
    db: Session = Depends(get_db),
    _: User = ViewerUser,
    limit: int = Query(default=25, ge=1, le=MAX_PAGE_SIZE),
    offset: int = Query(default=0, ge=0, le=1_000_000),
) -> Page[IngestionBatchRead]:
    total = int(db.scalar(select(func.count(IngestionBatch.id))) or 0)
    rows = list(
        db.scalars(
            select(IngestionBatch)
            .order_by(IngestionBatch.started_at.desc())
            .limit(limit)
            .offset(offset)
        )
    )
    return Page(
        items=[IngestionBatchRead.model_validate(r) for r in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@ingestion_router.get("/batches/{batch_id}", response_model=IngestionBatchRead)
def get_ingestion_batch(
    batch_id: uuid.UUID,
    db: Session = Depends(get_db),
    _: User = ViewerUser,
) -> IngestionBatch:
    batch = db.get(IngestionBatch, batch_id)
    if batch is None:
        raise NotFoundError("Ingestion batch not found")
    return batch
