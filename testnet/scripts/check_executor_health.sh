#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: check_executor_health.sh <host>:<port> [interval_seconds] [path]

HTTP-level probe loop to confirm the executor RPC responds over HTTP.
Defaults to POST /upload_ssh_key with a minimal payload that passes request validation.

Environment overrides:
  CHECK_EXECUTOR_METHOD   HTTP method to use (default: POST)
  CHECK_EXECUTOR_TIMEOUT  curl timeout in seconds (default: 5)
  CHECK_EXECUTOR_PAYLOAD  JSON payload to send (ignored for GET/HEAD)
USAGE
}

if [[ ${1:-} == "--help" ]]; then
  usage
  exit 0
fi

if [[ $# -lt 1 || $# -gt 3 ]]; then
  usage >&2
  exit 1
fi

target=$1
interval=${2:-5}
path=${3:-/upload_ssh_key}
method=${CHECK_EXECUTOR_METHOD:-POST}
timeout=${CHECK_EXECUTOR_TIMEOUT:-5}
method=${method^^}
default_payload='{"data_to_sign":"","signature":"","public_key":""}'
payload=${CHECK_EXECUTOR_PAYLOAD:-$default_payload}

if [[ ! $target =~ ^[^:]+:[0-9]+$ ]]; then
  echo "Target must be in host:port format" >&2
  exit 1
fi

if ! [[ $interval =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
  echo "Interval must be numeric" >&2
  exit 1
fi

if [[ $path != /* ]]; then
  echo "Path must start with '/'" >&2
  exit 1
fi

host=${target%:*}
port=${target##*:}

COLOR_GREEN="\033[0;32m"
COLOR_YELLOW="\033[0;33m"
COLOR_RED="\033[0;31m"
COLOR_RESET="\033[0m"

probe() {
  local status color body http_code
  status="UNREACHABLE"
  color=$COLOR_RED
  http_code="-"

  curl_args=(--silent --show-error --max-time "$timeout" --write-out '\n%{http_code}' -X "$method")

  if [[ ! $method =~ ^(GET|HEAD)$ ]]; then
    curl_args+=(-H "Content-Type: application/json" -d "$payload")
  fi

  request_url="http://$host:$port$path"
  curl_args+=("$request_url")

  if output=$(curl "${curl_args[@]}" 2>&1); then
    http_code=${output##*$'\n'}
    body=${output%$'\n'$http_code}

    if [[ $http_code =~ ^[0-9]{3}$ ]]; then
      code_num=$http_code
      if (( code_num >= 200 && code_num < 300 )); then
        status="OK"
        color=$COLOR_GREEN
      elif (( code_num >= 300 && code_num < 400 )); then
        status="REDIRECT"
        color=$COLOR_YELLOW
      elif (( code_num == 401 )); then
        status="AUTH NEEDED"
        color=$COLOR_GREEN
      elif (( code_num >= 400 && code_num < 500 )); then
        status="CLIENT ERROR"
        color=$COLOR_YELLOW
      elif (( code_num >= 500 && code_num < 600 )); then
        status="SERVER ERROR"
        color=$COLOR_YELLOW
      else
        status="HTTP ${http_code}"
        color=$COLOR_YELLOW
      fi
    else
      status="NO CODE"
      color=$COLOR_RED
    fi
  else
    body=$output
  fi

  printf '[%s] %b%s%b (code=%s)\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$color" "$status" "$COLOR_RESET" "$http_code"
  if [[ -n ${body:-} ]]; then
    printf '  %s\n' "$body"
  fi
}

trap 'echo; echo "Stopping health check"; exit' INT TERM

echo "Probing executor RPC at $host:$port every $interval second(s) via $method $path"

while true; do
  probe
  sleep "$interval"
done
