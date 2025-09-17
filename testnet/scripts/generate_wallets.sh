#!/usr/bin/env bash
set -euo pipefail

TESTNET_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
MINER_DIR="$TESTNET_ROOT/miner"
VALIDATOR_DIR="$TESTNET_ROOT/validator"
MINER_ENV="$MINER_DIR/.env"
VALIDATOR_ENV="$VALIDATOR_DIR/.env"

if [[ ! -f "$MINER_ENV" ]]; then
  echo "Miner .env not found at $MINER_ENV" >&2
  exit 1
fi

if [[ ! -f "$VALIDATOR_ENV" ]]; then
  echo "Validator .env not found at $VALIDATOR_ENV" >&2
  exit 1
fi

# shellcheck disable=SC1090
source "$MINER_ENV"

WALLET_NAME=${BITTENSOR_WALLET_NAME:-testnet}
MINER_HOTKEY_NAME=${BITTENSOR_WALLET_HOTKEY_NAME:-miner_hot}
VALIDATOR_HOTKEY_NAME=${TESTNET_VALIDATOR_HOTKEY_NAME:-validator_hot}
WALLET_DIR=${BITTENSOR_WALLET_DIRECTORY:-$TESTNET_ROOT/wallets}
mkdir -p "$WALLET_DIR"

COMPOSE_CMD=(docker compose -f "$MINER_DIR/docker-compose.yml")
run_miner() {
  "${COMPOSE_CMD[@]}" run --rm miner "$@"
}

if ! docker network inspect testnet-net >/dev/null 2>&1; then
  docker network create testnet-net >/dev/null
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
    "MINER_HOTKEY_SS58": addresses.get("HOTKEY:miner_hot"),
    "TESTNET_VALIDATOR_HOTKEY": addresses.get("HOTKEY:validator_hot"),
}

validator_updates = {
    "TARGET_MINER_HOTKEY": addresses.get("HOTKEY:miner_hot"),
    "VALIDATOR_HOTKEY_SS58": addresses.get("HOTKEY:validator_hot"),
}

def update_env(path_str, mapping):
    path = Path(path_str)
    text = path.read_text()
    for key, value in mapping.items():
        if not value:
            continue
        pattern = re.compile(rf'^{key}=.*$', re.MULTILINE)
        replacement = f"{key}={value}"
        if pattern.search(text):
            text = pattern.sub(replacement, text)
        else:
            if not text.endswith("\n"):
                text += "\n"
            text += replacement + "\n"
    path.write_text(text)

update_env(os.environ["MINER_ENV"], updates)
update_env(os.environ["VALIDATOR_ENV"], validator_updates)
PY

run_miner pdm run btcli wallet list --wallet-path /root/.bittensor/wallets
