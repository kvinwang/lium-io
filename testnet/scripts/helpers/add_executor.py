"""Add or update validator/executor records in the local miner database."""

from __future__ import annotations

import argparse
import sys
from uuid import UUID, uuid4

from sqlmodel import Session, select

from core.config import settings
from core.db import engine
from models.executor import Executor
from models.validator import Validator


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--validator", required=True, help="Validator hotkey")
    parser.add_argument("--address", required=True, help="Executor host or IP")
    parser.add_argument("--port", type=int, required=True, help="Executor API port")
    parser.add_argument(
        "--price",
        type=float,
        default=0.0,
        help="Hourly price for the executor (default: 0.0)",
    )
    parser.add_argument(
        "--validator-uuid",
        dest="validator_uuid",
        type=UUID,
        required=False,
        help="Optional validator UUID override",
    )
    parser.add_argument(
        "--executor-uuid",
        dest="executor_uuid",
        type=UUID,
        required=False,
        help="Optional executor UUID override",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.port <= 0:
        raise SystemExit("Executor port must be a positive integer")
    if args.price < 0:
        raise SystemExit("Hourly price cannot be negative")

    validator_uuid = args.validator_uuid or uuid4()
    executor_uuid = args.executor_uuid or uuid4()

    print("Connecting to database:", settings.SQLALCHEMY_DATABASE_URI)

    with Session(engine) as session:
        validator = (
            session.exec(select(Validator).where(Validator.validator_hotkey == args.validator)).first()
        )
        if validator is None:
            validator = Validator(
                uuid=validator_uuid,
                validator_hotkey=args.validator,
                active=True,
            )
            session.add(validator)
            print(f"Inserted validator {args.validator}")
        else:
            updated = False
            if args.validator_uuid and validator.uuid != args.validator_uuid:
                validator.uuid = args.validator_uuid
                updated = True
            if not validator.active:
                validator.active = True
                updated = True
            if updated:
                session.add(validator)
                print(f"Updated validator {args.validator}")
            else:
                print(f"Validator {args.validator} already present")

        executor = (
            session.exec(
                select(Executor).where(
                    (Executor.address == args.address) & (Executor.port == args.port)
                )
            ).first()
        )
        if executor is None:
            executor = Executor(
                uuid=executor_uuid,
                address=args.address,
                port=args.port,
                validator=args.validator,
                price_per_hour=args.price,
            )
            session.add(executor)
            print(f"Inserted executor {args.address}:{args.port}")
        else:
            updated = False
            if args.executor_uuid and executor.uuid != args.executor_uuid:
                executor.uuid = args.executor_uuid
                updated = True
            if executor.validator != args.validator:
                executor.validator = args.validator
                updated = True
            if executor.price_per_hour != args.price:
                executor.price_per_hour = args.price
                updated = True
            if updated:
                session.add(executor)
                print(f"Updated executor {args.address}:{args.port}")
            else:
                print(f"Executor {args.address}:{args.port} already present")

        session.commit()

    print("Add operation complete.")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # pragma: no cover - surfaced to stdout for convenience
        print(f"Add operation failed: {exc}", file=sys.stderr)
        raise
