#!/usr/bin/env bash
set -euo pipefail

TESTNET_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
MINER_DIR="$TESTNET_ROOT/miner"
VALIDATOR_DIR="$TESTNET_ROOT/validator"
MINER_ENV="$MINER_DIR/.env"
VALIDATOR_ENV="$VALIDATOR_DIR/.env"
MINER_ENV_EXAMPLE="$MINER_DIR/.env.example"
VALIDATOR_ENV_EXAMPLE="$VALIDATOR_DIR/.env.example"

if [[ ! -f "$MINER_ENV" ]]; then
  if [[ -f "$MINER_ENV_EXAMPLE" ]]; then
    cp "$MINER_ENV_EXAMPLE" "$MINER_ENV"
    echo "Created miner .env from example: $MINER_ENV"
  else
    echo "Miner .env not found and example missing ($MINER_ENV_EXAMPLE)" >&2
    exit 1
  fi
fi

if [[ ! -f "$VALIDATOR_ENV" ]]; then
  if [[ -f "$VALIDATOR_ENV_EXAMPLE" ]]; then
    cp "$VALIDATOR_ENV_EXAMPLE" "$VALIDATOR_ENV"
    echo "Created validator .env from example: $VALIDATOR_ENV"
  else
    echo "Validator .env not found and example missing ($VALIDATOR_ENV_EXAMPLE)" >&2
    exit 1
  fi
fi

# shellcheck disable=SC1090
source "$MINER_ENV"

WALLET_NAME=${BITTENSOR_WALLET_NAME:-testnet}
MINER_HOTKEY_NAME=${BITTENSOR_WALLET_HOTKEY_NAME:-miner_hot}
VALIDATOR_HOTKEY_NAME=${TESTNET_VALIDATOR_HOTKEY_NAME:-validator_hot}
WALLET_DIR=${BITTENSOR_WALLET_DIRECTORY:-$TESTNET_ROOT/wallets}
mkdir -p "$WALLET_DIR"

export MINER_HOTKEY_NAME VALIDATOR_HOTKEY_NAME

COMPOSE_CMD=(docker compose -f "$MINER_DIR/docker-compose.yml")
run_miner() {
  "${COMPOSE_CMD[@]}" run --rm miner "$@"
}

if ! docker network inspect lium-testnet >/dev/null 2>&1; then
  docker network create lium-testnet >/dev/null
fi

COLDKEY_PUB="$WALLET_DIR/$WALLET_NAME/coldkeypub.txt"
if [[ -f "$COLDKEY_PUB" ]]; then
  echo "Coldkey already exists at $COLDKEY_PUB, skipping creation"
else
  echo "Creating coldkey and miner hotkey..."
  run_miner pdm run btcli wallet create \
    --wallet-name "$WALLET_NAME" \
    --wallet-path /root/.bittensor/wallets \
    --hotkey "$MINER_HOTKEY_NAME" \
    --no-use-password \
    --n-words 12 \
    --quiet
fi

MINER_HOTKEY_FILE="$WALLET_DIR/$WALLET_NAME/hotkeys/$MINER_HOTKEY_NAME"
if [[ -f "$MINER_HOTKEY_FILE" ]]; then
  echo "Miner hotkey file found at $MINER_HOTKEY_FILE"
else
  echo "Creating miner hotkey $MINER_HOTKEY_NAME"
  run_miner pdm run btcli wallet new-hotkey \
    --wallet-name "$WALLET_NAME" \
    --wallet-path /root/.bittensor/wallets \
    --hotkey "$MINER_HOTKEY_NAME" \
    --no-use-password \
    --n-words 12 \
    --quiet
fi

VALIDATOR_HOTKEY_FILE="$WALLET_DIR/$WALLET_NAME/hotkeys/$VALIDATOR_HOTKEY_NAME"
if [[ -f "$VALIDATOR_HOTKEY_FILE" ]]; then
  echo "Validator hotkey file found at $VALIDATOR_HOTKEY_FILE"
else
  echo "Creating validator hotkey $VALIDATOR_HOTKEY_NAME"
  run_miner pdm run btcli wallet new-hotkey \
    --wallet-name "$WALLET_NAME" \
    --wallet-path /root/.bittensor/wallets \
    --hotkey "$VALIDATOR_HOTKEY_NAME" \
    --no-use-password \
    --n-words 12 \
    --quiet
fi

export WALLET_LIST_OUTPUT
WALLET_LIST_OUTPUT=$(run_miner pdm run btcli wallet list --wallet-path /root/.bittensor/wallets --json-output)

export MINER_ENV VALIDATOR_ENV
python - <<'PY'
import json
import os
import re
from pathlib import Path

output = os.environ["WALLET_LIST_OUTPUT"]
miner_hotkey_name = os.environ.get("MINER_HOTKEY_NAME", "miner_hot")
validator_hotkey_name = os.environ.get("VALIDATOR_HOTKEY_NAME", "validator_hot")

match = re.search(r'(\{.*\})', output, re.S)
if not match:
    raise SystemExit("Failed to parse wallet list output")
info = json.loads(match.group(1))
wallets = info.get("wallets", [])
if not wallets:
    raise SystemExit("No wallets found in wallet list output")
wallet = wallets[0]
addresses = {
    "COLDKEY": wallet.get("ss58_address"),
}
for hotkey in wallet.get("hotkeys", []):
    addresses[f"HOTKEY:{hotkey['name']}"] = hotkey.get("ss58_address")

updates = {
    "MINER_HOTKEY_SS58": addresses.get(f"HOTKEY:{miner_hotkey_name}"),
    "TESTNET_VALIDATOR_HOTKEY": addresses.get(f"HOTKEY:{validator_hotkey_name}"),
}

validator_updates = {
    "TARGET_MINER_HOTKEY": addresses.get(f"HOTKEY:{miner_hotkey_name}"),
    "VALIDATOR_HOTKEY_SS58": addresses.get(f"HOTKEY:{validator_hotkey_name}"),
}

def update_env(path_str, mapping, label):
    path = Path(path_str)
    text = path.read_text()
    changes: list[str] = []
    for key, value in mapping.items():
        if not value:
            continue
        pattern = re.compile(rf'^{key}=.*$', re.MULTILINE)
        replacement = f"{key}={value}"
        match = pattern.search(text)
        if match:
            if match.group(0) == replacement:
                changes.append(f"  {key}: already {value}")
            else:
                text = pattern.sub(replacement, text)
                changes.append(f"  {key}: updated -> {value}")
        else:
            if not text.endswith("\n"):
                text += "\n"
            text += replacement + "\n"
            changes.append(f"  {key}: added -> {value}")
    path.write_text(text)
    if changes:
        print(f"Updated {label} ({path}):")
        for change in changes:
            print(change)
    else:
        print(f"Updated {label} ({path}): no changes")


update_env(os.environ["MINER_ENV"], updates, "miner .env")
update_env(os.environ["VALIDATOR_ENV"], validator_updates, "validator .env")
PY

run_miner pdm run btcli wallet list --wallet-path /root/.bittensor/wallets
