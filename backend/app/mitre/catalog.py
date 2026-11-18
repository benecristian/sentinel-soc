"""MITRE ATT&CK catalog loader and coverage computation."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.models import Alert, DetectionRule, MitreTactic, MitreTechnique, RuleTechnique

CoverageStatus = Literal["implemented", "disabled", "documented"]

_DATA_FILE = Path(__file__).parent / "data" / "attack_subset.json"


@lru_cache(maxsize=1)
def load_attack_bundle() -> dict[str, Any]:
    with _DATA_FILE.open("r", encoding="utf-8") as fh:
        data: dict[str, Any] = json.load(fh)
        return data


def compute_mitre_techniques(
    db: Session,
    *,
    tactic_id: str | None = None,
    coverage_filter: CoverageStatus | None = None,
) -> list[dict[str, Any]]:
    techniques = list(
        db.scalars(
            select(MitreTechnique)
            .options(selectinload(MitreTechnique.tactics))
            .order_by(MitreTechnique.id)
        )
    )
    rule_links = list(db.scalars(select(RuleTechnique).options(selectinload(RuleTechnique.rule))))
    alert_counts = dict(
        db.execute(
            select(Alert.mitre_technique_id, func.count(Alert.id))
            .where(Alert.mitre_technique_id.is_not(None))
            .group_by(Alert.mitre_technique_id)
        ).all()
    )

    rules_by_tech: dict[str, list[tuple[DetectionRule, bool]]] = {}
    for link in rule_links:
        if link.rule is not None:
            rules_by_tech.setdefault(link.technique_id, []).append((link.rule, link.is_primary))

    results: list[dict[str, Any]] = []
    for tech in techniques:
        if tactic_id and not any(
            t.id == tactic_id or t.shortname == tactic_id for t in tech.tactics
        ):
            continue

        mapped_rules = rules_by_tech.get(tech.id, [])
        if any(r.enabled for r, _ in mapped_rules):
            coverage: CoverageStatus = "implemented"
        elif mapped_rules:
            coverage = "disabled"
        else:
            coverage = "documented"

        if coverage_filter and coverage != coverage_filter:
            continue

        results.append(
            {
                "id": tech.id,
                "name": tech.name,
                "description": tech.description,
                "parent_id": tech.parent_id,
                "url": tech.url,
                "attack_version": tech.attack_version,
                "coverage": coverage,
                "alert_count": int(alert_counts.get(tech.id, 0)),
                "tactics": [
                    {"id": t.id, "name": t.name, "shortname": t.shortname}
                    for t in sorted(tech.tactics, key=lambda x: x.display_order)
                ],
                "rules": [
                    {
                        "id": r.id,
                        "name": r.name,
                        "severity": r.severity,
                        "enabled": r.enabled,
                        "is_primary": is_primary,
                    }
                    for r, is_primary in sorted(mapped_rules, key=lambda x: x[0].id)
                ],
            }
        )
    return results


def compute_mitre_coverage_matrix(db: Session) -> dict[str, Any]:
    bundle = load_attack_bundle()
    tactics = list(db.scalars(select(MitreTactic).order_by(MitreTactic.display_order)))
    all_techniques = compute_mitre_techniques(db)

    implemented_count = sum(1 for t in all_techniques if t["coverage"] == "implemented")
    disabled_count = sum(1 for t in all_techniques if t["coverage"] == "disabled")
    documented_count = sum(1 for t in all_techniques if t["coverage"] == "documented")

    tactic_columns: list[dict[str, Any]] = []
    for tactic in tactics:
        tactic_techs = [
            t for t in all_techniques if any(tc["id"] == tactic.id for tc in t["tactics"])
        ]
        tactic_columns.append(
            {
                "id": tactic.id,
                "name": tactic.name,
                "shortname": tactic.shortname,
                "description": tactic.description,
                "url": tactic.url,
                "display_order": tactic.display_order,
                "implemented_count": sum(1 for t in tactic_techs if t["coverage"] == "implemented"),
                "total_count": len(tactic_techs),
                "techniques": tactic_techs,
            }
        )

    return {
        "attack_version": bundle.get("attack_version", "16.1"),
        "attribution": bundle.get("attribution", ""),
        "summary": {
            "total_techniques": len(all_techniques),
            "implemented_count": implemented_count,
            "disabled_count": disabled_count,
            "documented_count": documented_count,
        },
        "tactics": tactic_columns,
    }
