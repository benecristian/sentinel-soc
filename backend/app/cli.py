"""Management CLI for seeding reference data, creating users and generating synthetic demo data.

Usage examples:
    python -m app.cli seed-reference
    python -m app.cli create-user --username admin --role admin --password-env SENTINEL_ADMIN_PASSWORD
    python -m app.cli seed-demo
"""

from __future__ import annotations

import argparse
import os
import sys

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.session import build_engine, build_session_factory
from app.domain.enums import IncidentStatus, Severity, UserRole
from app.models import Alert, Incident, User
from app.seeds.seeder import seed_reference_data
from app.services.incidents import add_incident_note, create_incident, update_incident
from app.services.users import UserCreationError, create_user
from app.simulation.runner import execute_simulation_scenario


def _open_session() -> Session:
    settings = get_settings()
    engine = build_engine(settings.database_url.get_secret_value())
    factory = build_session_factory(engine)
    return factory()


def cmd_seed_reference() -> None:
    with _open_session() as db:
        seed_reference_data(db)
    print("Reference data (MITRE ATT&CK catalog and 7 detection rules) seeded.")


def cmd_create_user(
    username: str,
    role: UserRole,
    display_name: str | None,
    password_env: str,
    if_not_exists: bool,
) -> None:
    password = os.environ.get(password_env)
    if not password:
        raise SystemExit(f"Environment variable {password_env!r} is not set or empty.")
    with _open_session() as db:
        if if_not_exists and db.scalar(select(User.id).where(User.username == username)):
            print(f"User {username!r} already exists; skipping.")
            return
        try:
            user = create_user(
                db,
                username=username,
                password=password,
                role=role,
                display_name=display_name,
            )
            db.commit()
            print(f"Created user {user.username!r} with role {user.role!r}.")
        except UserCreationError as exc:
            raise SystemExit(f"Failed to create user: {exc}") from exc


def cmd_seed_demo() -> None:
    """Seed reference data and execute synthetic scenarios + sample incident for demos."""
    with _open_session() as db:
        seed_reference_data(db)
        actor = db.scalar(select(User).order_by(User.created_at.asc()))

        for scenario_id in (
            "normal_activity",
            "ssh_brute_force",
            "password_spraying",
            "port_scan",
            "suspicious_dns",
            "suspicious_http",
            "privileged_activity",
        ):
            execute_simulation_scenario(db, scenario_id, triggered_by=actor.id if actor else None)
        db.commit()

        # Create a sample incident if none exist yet and we have an actor + alerts
        if actor and db.scalar(select(Incident.id).limit(1)) is None:
            alerts = list(db.scalars(select(Alert).order_by(Alert.created_at.asc()).limit(2)))
            if alerts:
                inc = create_incident(
                    db,
                    title="[SYNTHETIC] SSH Brute Force & Privilege Escalation Investigation",
                    description=(
                        "Synthetic demonstration incident grouping initial credential "
                        "brute-force alerts for analyst triage walkthrough."
                    ),
                    severity=Severity.CRITICAL,
                    lead_analyst_id=actor.id,
                    alert_ids=[a.id for a in alerts],
                    recommended_actions=[
                        "Block 203.0.113.45 at perimeter firewall.",
                        "Rotate credentials for account 'deploy' on bastion-01.",
                    ],
                    actor=actor,
                )
                update_incident(
                    db,
                    inc,
                    new_status=IncidentStatus.INVESTIGATING,
                    findings=(
                        "Synthetic simulation confirmed 24 failed SSH login attempts "
                        "from 203.0.113.45 followed by a successful login to 'deploy'."
                    ),
                    actor=actor,
                )
                add_incident_note(
                    db,
                    incident=inc,
                    body=(
                        "Confirmed synthetic brute-force pattern (T1110.001). "
                        "Initiated containment checklist on bastion-01."
                    ),
                    author=actor,
                )
                db.commit()
        print("Synthetic demo scenarios and sample incident seeded.")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="sentinel-cli")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("seed-reference", help="Seed MITRE catalog and detection rules")
    sub.add_parser("seed-demo", help="Seed reference data and run synthetic demo scenarios")

    p_user = sub.add_parser("create-user", help="Create a platform user")
    p_user.add_argument("--username", required=True)
    p_user.add_argument(
        "--role",
        choices=[r.value for r in UserRole],
        default=UserRole.ANALYST.value,
    )
    p_user.add_argument("--display-name", default=None)
    p_user.add_argument("--password-env", default="SENTINEL_USER_PASSWORD")
    p_user.add_argument("--if-not-exists", action="store_true")

    args = parser.parse_args(argv)
    if args.command == "seed-reference":
        cmd_seed_reference()
    elif args.command == "seed-demo":
        cmd_seed_demo()
    elif args.command == "create-user":
        cmd_create_user(
            username=args.username,
            role=UserRole(args.role),
            display_name=args.display_name,
            password_env=args.password_env,
            if_not_exists=args.if_not_exists,
        )
    else:
        sys.exit(2)


if __name__ == "__main__":
    main()
