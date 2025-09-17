"""Delete an executor from the local miner database."""

from __future__ import annotations

import argparse
import sys
import uuid

from sqlmodel import Session, select

from core.db import engine
from models.executor import Executor


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--uuid", dest="uuid", help="UUID of the executor to delete")
    group.add_argument("--address", dest="address", help="Executor address to delete")
    parser.add_argument("--port", dest="port", type=int, help="Port for the address match")
    args = parser.parse_args()

    if args.address and args.port is None:
        parser.error("--port is required when using --address")
    if args.port is not None and args.port <= 0:
        parser.error("--port must be a positive integer")

    if args.uuid:
        try:
            uuid.UUID(args.uuid)
        except ValueError as exc:  # pragma: no cover - CLI validation
            parser.error(f"Invalid UUID: {args.uuid}")
    return args


def main() -> int:
    args = parse_args()

    with Session(engine) as session:
        if args.uuid:
            key = uuid.UUID(args.uuid)
            executor = session.get(Executor, key)
        else:
            statement = select(Executor).where(
                (Executor.address == args.address) & (Executor.port == args.port)
            )
            executor = session.exec(statement).first()

        if executor is None:
            print("Executor not found.")
            return 1

        summary = f"{executor.uuid} ({executor.address}:{executor.port})"
        session.delete(executor)
        session.commit()

    print(f"Deleted executor {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
