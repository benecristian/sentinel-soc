"""Idempotent database seeder for MITRE ATT&CK catalog and detection rules."""

from __future__ import annotations

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.detection.rules import ALL_RULES
from app.mitre.catalog import load_attack_bundle
from app.models import (
    DetectionRule,
    MitreTactic,
    MitreTechnique,
    RuleTechnique,
    technique_tactics,
)


def seed_reference_data(db: Session) -> None:
    """Seed MITRE ATT&CK tactics/techniques and default detection rules idempotently."""
    bundle = load_attack_bundle()
    version = str(bundle["attack_version"])

    # 1. MITRE tactics
    for t in bundle["tactics"]:
        existing = db.get(MitreTactic, t["id"])
        if existing is None:
            db.add(
                MitreTactic(
                    id=t["id"],
                    name=t["name"],
                    shortname=t["shortname"],
                    description=t["description"],
                    url=t["url"],
                    display_order=int(t["display_order"]),
                )
            )
        else:
            existing.name = t["name"]
            existing.shortname = t["shortname"]
            existing.description = t["description"]
            existing.url = t["url"]
            existing.display_order = int(t["display_order"])
    db.flush()

    # 2. MITRE techniques (parents first, then sub-techniques)
    sorted_techs = sorted(
        bundle["techniques"], key=lambda item: (item["parent_id"] is not None, item["id"])
    )
    for tech in sorted_techs:
        existing_tech = db.get(MitreTechnique, tech["id"])
        if existing_tech is None:
            db.add(
                MitreTechnique(
                    id=tech["id"],
                    name=tech["name"],
                    description=tech["description"],
                    parent_id=tech["parent_id"],
                    url=tech["url"],
                    attack_version=version,
                )
            )
        else:
            existing_tech.name = tech["name"]
            existing_tech.description = tech["description"]
            existing_tech.parent_id = tech["parent_id"]
            existing_tech.url = tech["url"]
            existing_tech.attack_version = version
    db.flush()

    # 3. Technique <-> tactic links
    link_rows = [
        {"technique_id": tech["id"], "tactic_id": tactic_id}
        for tech in bundle["techniques"]
        for tactic_id in tech["tactics"]
    ]
    if link_rows:
        db.execute(pg_insert(technique_tactics).values(link_rows).on_conflict_do_nothing())

    # 4. Detection rules (preserve user-tuned threshold/window/enabled if row already exists)
    for rule_impl in ALL_RULES:
        meta = rule_impl.metadata
        rule_row = db.get(DetectionRule, meta.id)
        if rule_row is None:
            rule_row = DetectionRule(
                id=meta.id,
                name=meta.name,
                description=meta.description,
                category=meta.category,
                severity=meta.default_severity.value,
                enabled=True,
                threshold=meta.default_threshold,
                time_window_seconds=meta.default_time_window_seconds,
                parameters=dict(meta.default_parameters),
                investigation_steps=list(meta.investigation_steps),
                remediation_steps=list(meta.remediation_steps),
                version=1,
            )
            db.add(rule_row)
        else:
            rule_row.name = meta.name
            rule_row.description = meta.description
            rule_row.category = meta.category
            rule_row.investigation_steps = list(meta.investigation_steps)
            rule_row.remediation_steps = list(meta.remediation_steps)

        db.flush()
        db.execute(delete(RuleTechnique).where(RuleTechnique.rule_id == meta.id))
        for mapping in meta.mitre_mappings:
            if db.scalar(
                select(MitreTechnique.id).where(MitreTechnique.id == mapping.technique_id)
            ):
                db.add(
                    RuleTechnique(
                        rule_id=meta.id,
                        technique_id=mapping.technique_id,
                        is_primary=mapping.is_primary,
                    )
                )

    db.commit()
