"""List executors stored in the local miner database."""

from __future__ import annotations

import argparse

from sqlmodel import Session, select

from core.db import engine
from models.executor import Executor


def format_price(value: float | None) -> str:
    if value is None:
        return "-"
    formatted = f"{value:.6f}".rstrip("0").rstrip(".")
    return formatted or "0"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--validator",
        dest="validator",
        help="Filter executors by validator hotkey",
    )
    args = parser.parse_args()

    statement = select(Executor)
    if args.validator:
        statement = statement.where(Executor.validator == args.validator)
    statement = statement.order_by(Executor.address, Executor.port)

    with Session(engine) as session:
        executors = session.exec(statement).all()

    if not executors:
        if args.validator:
            print(f"No executors found for validator {args.validator}")
        else:
            print("No executors found.")
        return

    header = f"{'UUID':36}  {'ADDRESS':21}  {'PORT':5}  {'VALIDATOR':48}  {'PRICE/H'}"
    print(header)
    print("-" * len(header))
    for executor in executors:
        price_str = format_price(executor.price_per_hour)
        print(
            f"{str(executor.uuid):36}  "
            f"{executor.address:21}  "
            f"{executor.port:<5}  "
            f"{executor.validator:48}  "
            f"{price_str}"
        )


if __name__ == "__main__":
    main()
