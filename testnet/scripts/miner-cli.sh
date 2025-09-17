#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: miner-cli.sh <command> [options]

Utility wrapper for interacting with the local miner stack.

Commands:
  add           Register or update an executor using the helper script
  del           Remove an executor from the local miner database
  ls            Show executor rows currently stored in the miner database

Run "miner-cli.sh <command> --help" for command-specific options.
USAGE
}

add_executor_usage() {
  cat <<'USAGE'
Usage: miner-cli.sh add <address> <port> [price_per_hour]

Arguments:
  address         Executor host or IP address
  port            Executor port exposed to the miner
  price_per_hour  Optional hourly price (default: TESTNET_EXECUTOR_PRICE_PER_HOUR or 0.0)
USAGE
}

ls_usage() {
  cat <<'USAGE'
Usage: miner-cli.sh ls [--validator HOTKEY]

Options:
  --validator HOTKEY  Filter executors for a specific validator hotkey
USAGE
}

del_usage() {
  cat <<'USAGE'
Usage: miner-cli.sh del (--uuid UUID | <address> <port>)

Options:
  --uuid UUID  Delete the executor with the given UUID

Arguments:
  address      Executor host or IP address
  port         Executor port exposed to the miner

Either provide --uuid or an address/port pair.
USAGE
}

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
TESTNET_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
MINER_DIR="$TESTNET_ROOT/miner"
MINER_ENV="$MINER_DIR/.env"
COMPOSE_CMD=(docker compose -f "$MINER_DIR/docker-compose.yml")
HELPERS_CONTAINER_PATH="/opt/testnet/helpers"

ensure_helper_available() {
  local helper_name=$1
  local helper_path="$SCRIPT_DIR/helpers/$helper_name"
  if [[ ! -f "$helper_path" ]]; then
    echo "Helper script not found: $helper_path" >&2
    exit 1
  fi

  # Ensure the helper directory exists inside the container.
  "${COMPOSE_CMD[@]}" exec -T miner bash -lc "mkdir -p ${HELPERS_CONTAINER_PATH}" >/dev/null 2>&1 || true
  "${COMPOSE_CMD[@]}" cp "$helper_path" "miner:${HELPERS_CONTAINER_PATH}/${helper_name}" >/dev/null 2>&1 || true
}

if [[ ! -f "$MINER_ENV" ]]; then
  echo "Miner .env not found at $MINER_ENV" >&2
  exit 1
fi

# shellcheck disable=SC1090
source "$MINER_ENV"

ensure_miner_running() {
  local container_id
  container_id=$("${COMPOSE_CMD[@]}" ps --status running -q miner 2>/dev/null || true)
  if [[ -z $container_id ]]; then
    echo "Miner container is not running. Start it with: (cd $MINER_DIR && docker compose up -d)" >&2
    exit 1
  fi
}

run_helper_script() {
  ensure_miner_running
  local script_name=$1
  shift || true
  ensure_helper_available "$script_name"
  local script_args=""
  if [[ $# -gt 0 ]]; then
    printf -v script_args ' %q' "$@"
  fi
  local command="cd /root/app && PYTHONPATH=/root/app/src pdm run python ${HELPERS_CONTAINER_PATH}/${script_name}${script_args}"
  "${COMPOSE_CMD[@]}" exec -T miner bash -lc "$command"
}

add_cmd() {
  if [[ ${1:-} == "--help" ]]; then
    add_executor_usage
    return 0
  fi

  if [[ $# -lt 1 || $# -gt 3 ]]; then
    add_executor_usage >&2
    return 1
  fi

  if [[ -z ${TESTNET_VALIDATOR_HOTKEY:-} ]]; then
    echo "TESTNET_VALIDATOR_HOTKEY must be set in $MINER_ENV" >&2
    return 1
  fi

  local address=$1
  shift || true

  local port price
  case $# in
    1)
      port=$1
      price=${TESTNET_EXECUTOR_PRICE_PER_HOUR:-0.0}
      ;;
    2)
      port=$1
      price=$2
      ;;
    *)
      add_executor_usage >&2
      return 1
      ;;
  esac

  if [[ -z $port ]]; then
    echo "Executor port is required. Pass it as an argument" >&2
    return 1
  fi

  if ! [[ $port =~ ^[0-9]+$ ]]; then
    echo "Port must be an integer: $port" >&2
    return 1
  fi

  if [[ -z $price ]]; then
    price=0
  fi

  if ! [[ $price =~ ^-?[0-9]+(\.[0-9]+)?$ ]]; then
    echo "Price must be numeric: $price" >&2
    return 1
  fi

  printf 'Adding executor %s:%s (price %s)\n' "$address" "$port" "$price"
  run_helper_script \
    "add_executor.py" \
    --validator "$TESTNET_VALIDATOR_HOTKEY" \
    --address "$address" \
    --port "$port" \
    --price "$price"
}

ls_cmd() {
  local validator_filter=""

  while [[ $# -gt 0 ]]; do
    case $1 in
      --validator)
        shift
        if [[ $# -eq 0 ]]; then
          echo "--validator expects a hotkey" >&2
          return 1
        fi
        validator_filter=$1
        ;;
      --help)
        ls_usage
        return 0
        ;;
      *)
        echo "Unknown option for ls: $1" >&2
        return 1
        ;;
    esac
    shift || true
  done

  if [[ -n $validator_filter ]]; then
    run_helper_script "list_executors.py" --validator "$validator_filter"
  else
    run_helper_script "list_executors.py"
  fi
}

del_cmd() {
  if [[ ${1:-} == "--help" ]]; then
    del_usage
    return 0
  fi

  local uuid_filter=""
  local address=""
  local port=""

  if [[ $# -eq 0 ]]; then
    del_usage >&2
    return 1
  fi

  if [[ $1 == "--uuid" ]]; then
    shift
    if [[ $# -eq 0 ]]; then
      echo "--uuid requires a value" >&2
      return 1
    fi
    uuid_filter=$1
    shift || true
  else
    if [[ $# -ne 2 ]]; then
      del_usage >&2
      return 1
    fi
    address=$1
    port=$2
    shift 2 || true
  fi

  if [[ -n $uuid_filter ]]; then
    if [[ ! $uuid_filter =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
      echo "Invalid UUID format: $uuid_filter" >&2
      return 1
    fi
  else
    if [[ ! $port =~ ^[0-9]+$ ]]; then
      echo "Port must be an integer: $port" >&2
      return 1
    fi
  fi

  if [[ $# -gt 0 ]]; then
    echo "Too many arguments provided for del" >&2
    return 1
  fi

  if [[ -n $uuid_filter ]]; then
    run_helper_script "delete_executor.py" --uuid "$uuid_filter"
  else
    run_helper_script "delete_executor.py" --address "$address" --port "$port"
  fi
}

main() {
  if [[ $# -eq 0 ]]; then
    usage >&2
    exit 1
  fi

  local cmd=$1
  shift || true

  case $cmd in
    add)
      add_cmd "$@"
      ;;
    del)
      del_cmd "$@"
      ;;
    ls)
      ls_cmd "$@"
      ;;
    --help|-h)
      usage
      ;;
    *)
      echo "Unknown command: $cmd" >&2
      usage >&2
      exit 1
      ;;
  esac
}

main "$@"
