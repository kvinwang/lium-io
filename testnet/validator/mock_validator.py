"""Mock validator with a simple web UI for local renting tests.

This version avoids repository-specific imports by constructing and parsing the
miner protocol messages directly as JSON objects.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import asyncssh
import bittensor
import websockets
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi import FastAPI, HTTPException, Request
from fastapi import WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse

try:  # Optional dependency used when verifying SGX quotes
    import httpx
except ImportError:  # pragma: no cover - surfaced via HTTP errors
    httpx = None  # type: ignore[assignment]

LOGGER = logging.getLogger("mock-validator")
logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s - %(message)s")

TEMPLATE_PATH = Path(__file__).parent / "templates" / "index.html"
HTML_TEMPLATE = TEMPLATE_PATH.read_text(encoding="utf-8")

REQUEST_AUTHENTICATE = "AuthenticateRequest"
REQUEST_SUBMIT_SSH_KEY = "SSHPubKeySubmitRequest"
RESPONSE_ACCEPT_JOB = "AcceptJobRequest"
RESPONSE_ACCEPT_SSH = "AcceptSSHKeyRequest"
RESPONSE_FAILED = "FailedRequest"
RESPONSE_DECLINE = "DeclineJobRequest"

DEFAULT_VERIFIER_URL = "http://dstack-verifier:8080"
QUOTE_REPORT_PREFIX = b"dip1:inline:lium:"


def _required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"Environment variable {name} must be set")
    return value


def _wallet_directory() -> Path:
    directory = os.environ.get("BITTENSOR_WALLET_DIRECTORY")
    return Path(directory).expanduser() if directory else Path("~/.bittensor/wallets").expanduser()


def load_validator_keypair() -> bittensor.Keypair:
    wallet_name = _required_env("BITTENSOR_WALLET_NAME")
    hotkey_name = _required_env("BITTENSOR_WALLET_HOTKEY_NAME")
    wallet = bittensor.wallet(
        name=wallet_name,
        hotkey=hotkey_name,
        path=str(_wallet_directory()),
    )
    return wallet.get_hotkey()


def generate_ssh_keypair(prefix: str, output_dir: Path) -> tuple[bytes, Path, Path]:
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    )

    timestamp = int(time.time())
    private_path = output_dir / f"{prefix}-{timestamp}-id_ed25519"
    public_path = output_dir / f"{prefix}-{timestamp}.pub"

    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)

    private_path.write_bytes(private_bytes)
    public_path.write_bytes(public_bytes)
    os.chmod(private_path, 0o600)

    LOGGER.info("Generated SSH keypair at %s", private_path)
    return public_bytes, private_path, public_path


def build_auth_message(validator_keypair: bittensor.Keypair, miner_hotkey: str) -> str:
    payload = {
        "validator_hotkey": validator_keypair.ss58_address,
        "miner_hotkey": miner_hotkey,
        "timestamp": int(time.time()),
    }
    signature = f"0x{validator_keypair.sign(json.dumps(payload, sort_keys=True)).hex()}"
    message = {
        "message_type": REQUEST_AUTHENTICATE,
        "payload": payload,
        "signature": signature,
    }
    return json.dumps(message)


def build_submit_message(public_key: bytes, executor_id: str | None) -> str:
    payload = {
        "message_type": REQUEST_SUBMIT_SSH_KEY,
        "public_key": public_key.decode(),
        "executor_id": executor_id,
        "is_rental_request": False,
    }
    return json.dumps(payload)


def parse_message(raw: str) -> dict[str, Any]:
    try:
        obj = json.loads(raw)
        if not isinstance(obj, dict) or "message_type" not in obj:
            raise ValueError("Invalid message structure")
        return obj
    except json.JSONDecodeError as exc:  # pragma: no cover - debugging aid
        raise ValueError(f"Malformed JSON: {exc}") from exc


def _generate_report_data() -> tuple[str, bytes]:
    nonce = os.urandom(20)
    report_bytes = QUOTE_REPORT_PREFIX + nonce
    return report_bytes.hex(), nonce


@dataclass
class RunState:
    status: str = "idle"
    message: str = "Ready"
    executor_id: str | None = None
    private_key_path: str | None = None
    public_key_path: str | None = None
    accept_payload_path: str | None = None
    executor_count: int = 0
    executors: list[dict[str, Any]] = field(default_factory=list)
    last_error: str | None = None
    started_at: float | None = None
    finished_at: float | None = None
    last_update: float = field(default_factory=time.time)
    compose_history: list[dict[str, Any]] = field(default_factory=list)
    running_containers: list[dict[str, Any]] = field(default_factory=list)
    verification_status: str | None = None
    verification_message: str | None = None
    verification_result: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "message": self.message,
            "executor_id": self.executor_id,
            "private_key_path": self.private_key_path,
            "public_key_path": self.public_key_path,
            "accept_payload_path": self.accept_payload_path,
            "executor_count": self.executor_count,
            "executors": self.executors,
            "last_error": self.last_error,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "last_update": self.last_update,
            "verification_status": self.verification_status,
            "verification_message": self.verification_message,
            "verification_result": self.verification_result,
        }


class MockValidatorService:
    def __init__(self) -> None:
        self.validator_keypair = load_validator_keypair()
        expected = os.environ.get("VALIDATOR_HOTKEY_SS58")
        if expected and expected != self.validator_keypair.ss58_address:
            LOGGER.warning(
                "Validator hotkey mismatch: wallet=%s, expected=%s",
                self.validator_keypair.ss58_address,
                expected,
            )

        self.miner_host = os.environ.get("MINER_HOST", "miner")
        self.miner_port = int(os.environ.get("MINER_PORT", "18080"))
        self.miner_hotkey = _required_env("TARGET_MINER_HOTKEY")
        self.executor_id_env = os.environ.get("TARGET_EXECUTOR_ID") or None
        self.retry_delay = float(os.environ.get("CONNECT_RETRY_SECONDS", "5"))
        self.timeout = float(os.environ.get("REQUEST_TIMEOUT_SECONDS", "60"))
        self.output_dir = Path(os.environ.get("SSH_KEY_OUTPUT_DIR", "/data/keys")).expanduser()
        self.accept_path = Path(
            os.environ.get(
                "ACCEPT_DETAILS_PATH",
                self.output_dir / "latest_accept.json",
            )
        ).expanduser()
        self.key_prefix = os.environ.get("SSH_KEY_PREFIX", "mock-validator")
        self.dstack_socket = os.environ.get("DSTACK_SOCKET", "/var/run/dstack.sock")
        self.quote_timeout = float(os.environ.get("QUOTE_TIMEOUT_SECONDS", "30"))
        self.verifier_url = os.environ.get("VERIFIER_URL", DEFAULT_VERIFIER_URL)
        self.verifier_timeout = float(os.environ.get("VERIFIER_TIMEOUT_SECONDS", "30"))

        self.state = RunState()
        self.latest_payload: dict[str, Any] | None = None
        self._current_task: asyncio.Task | None = None
        self._lock = asyncio.Lock()
        self._last_generated_keypair: tuple[str | None, str | None] = (None, None)
        self.compose_history: list[dict[str, Any]] = []
        self.running_containers: list[dict[str, Any]] = []

    def _update_state(self, **changes: Any) -> None:
        for field_name, value in changes.items():
            setattr(self.state, field_name, value)
        self.state.compose_history = list(self.compose_history)
        self.state.running_containers = list(self.running_containers)
        self.state.last_update = time.time()
        LOGGER.info("State update: %s", json.dumps(self.state.to_dict(), indent=2))

    async def start_request(self, executor_id: str | None) -> RunState:
        async with self._lock:
            if self._current_task and not self._current_task.done():
                raise RuntimeError("A request is already running")
            target_executor = executor_id or self.executor_id_env
            self._update_state(
                status="running",
                message="Generating SSH key",
                executor_id=target_executor,
                private_key_path=None,
                public_key_path=None,
                accept_payload_path=None,
                executor_count=0,
                executors=[],
                last_error=None,
                started_at=time.time(),
                finished_at=None,
                verification_status=None,
                verification_message=None,
                verification_result=None,
            )
            self._current_task = asyncio.create_task(self._execute(target_executor))
        return self.state

    async def _execute(self, executor_id: str | None) -> None:
        try:
            public_key, private_path, public_path = generate_ssh_keypair(
                self.key_prefix,
                self.output_dir,
            )
            self._update_state(
                private_key_path=str(private_path),
                public_key_path=str(public_path),
                message="Connecting to miner",
            )
            self._last_generated_keypair = (str(private_path), str(public_path))
            accept = await self._perform_request(executor_id, public_key)
            payload = self._store_accept_payload(accept, private_path, public_path)
            self.latest_payload = payload
            self._update_state(
                status="success",
                message=f"SSH key accepted by {len(accept['executors'])} executor(s)",
                executor_count=len(accept["executors"]),
                executors=payload["executors"],
                accept_payload_path=str(self.accept_path),
                last_error=None,
                finished_at=time.time(),
            )
        except Exception as exc:  # pragma: no cover - surfaced to UI
            LOGGER.error("Request failed: %s", exc, exc_info=True)
            self._update_state(
                status="error",
                message="Request failed",
                last_error=str(exc),
                finished_at=time.time(),
            )
        finally:
            async with self._lock:
                self._current_task = None

    async def _perform_request(
        self,
        executor_id: str | None,
        public_key: bytes,
    ) -> dict[str, Any]:
        submit_request = build_submit_message(public_key, executor_id)
        ws_url = (
            f"ws://{self.miner_host}:{self.miner_port}/websocket/"
            f"{self.validator_keypair.ss58_address}"
        )

        while True:
            try:
                LOGGER.info("Connecting to miner at %s", ws_url)
                async with websockets.connect(ws_url, max_size=50 * (2**20)) as ws:
                    self._update_state(message="Authenticating with miner")
                    await ws.send(build_auth_message(self.validator_keypair, self.miner_hotkey))

                    self._update_state(message="Submitting SSH public key")
                    await ws.send(submit_request)

                    while True:
                        raw_msg = await asyncio.wait_for(ws.recv(), timeout=self.timeout)
                        msg = parse_message(raw_msg)
                        mtype = msg.get("message_type")

                        if mtype == RESPONSE_ACCEPT_JOB:
                            executors = msg.get("executors") or []
                            self._update_state(
                                message=(
                                    "Miner ready with "
                                    f"{len(executors)} executor(s)"
                                ),
                            )
                            continue

                        if mtype == RESPONSE_ACCEPT_SSH:
                            return msg

                        if mtype in (RESPONSE_FAILED, RESPONSE_DECLINE):
                            raise RuntimeError(json.dumps(msg))

                        LOGGER.info("Received message: %s", raw_msg)
            except (OSError, websockets.WebSocketException) as exc:
                LOGGER.warning("Connection error: %s", exc)
                self._update_state(
                    message="Connection error, retrying...",
                    last_error=str(exc),
                )
                await asyncio.sleep(self.retry_delay)
            except asyncio.TimeoutError:
                LOGGER.warning("Timed out waiting for miner response")
                self._update_state(
                    message="Timeout waiting for miner, retrying...",
                    last_error="timeout",
                )
                await asyncio.sleep(self.retry_delay)

    def _store_accept_payload(
        self,
        accept: dict[str, Any],
        private_key_path: Path,
        public_key_path: Path,
    ) -> dict[str, Any]:
        payload = {
            "received_at": time.time(),
            "private_key_path": str(private_key_path),
            "public_key_path": str(public_key_path),
            "executors": accept.get("executors", []),
        }
        self.accept_path.parent.mkdir(parents=True, exist_ok=True)
        self.accept_path.write_text(json.dumps(payload, indent=2))
        LOGGER.info("Stored accept payload at %s", self.accept_path)
        return payload

    async def _call_verifier(self, quote_json_text: str) -> dict[str, Any]:
        if httpx is None:
            raise RuntimeError(
                "httpx package is required to contact dstack-verifier. Install with `pip install httpx`."
            )

        base_url = (self.verifier_url or DEFAULT_VERIFIER_URL).strip()
        if not base_url:
            base_url = DEFAULT_VERIFIER_URL
        if not base_url.lower().startswith("http"):
            base_url = f"http://{base_url}"
        url = base_url.rstrip("/")
        if not url.endswith("/verify"):
            url = f"{url}/verify"

        LOGGER.info("Submitting quote to dstack-verifier at %s", url)

        try:
            async with httpx.AsyncClient(timeout=self.verifier_timeout) as client:
                response = await client.post(
                    url,
                    content=quote_json_text.encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                )
        except httpx.HTTPError as exc:  # pragma: no cover - network dependency
            raise RuntimeError(f"Verifier request failed: {exc}") from exc

        if response.status_code >= 400:
            snippet = response.text[:200] if response.text else "<empty>"
            raise RuntimeError(
                f"Verifier request returned {response.status_code}: {snippet}"
            )

        try:
            return response.json()
        except ValueError as exc:  # pragma: no cover - defensive
            raise RuntimeError("Verifier response was not valid JSON") from exc

    def _update_executor_verification(
        self,
        executor_uuid: str,
        verification: dict[str, Any],
    ) -> list[dict[str, Any]]:
        def _patch(executors: list[dict[str, Any]] | None) -> tuple[list[dict[str, Any]], bool]:
            items: list[dict[str, Any]] = []
            found = False
            for entry in executors or []:
                data = dict(entry)
                if data.get("uuid") == executor_uuid:
                    data = {**data, "verification": verification}
                    found = True
                items.append(data)
            return items, found

        payload_executors, found_payload = _patch(
            (self.latest_payload or {}).get("executors") if self.latest_payload else None
        )

        state_executors, found_state = _patch(self.state.executors or [])

        if self.latest_payload is not None and (found_payload or payload_executors):
            self.latest_payload["executors"] = payload_executors
            try:
                self.accept_path.write_text(json.dumps(self.latest_payload, indent=2))
            except Exception as exc:  # pragma: no cover - best effort persistence
                LOGGER.warning("Failed to persist updated verification data: %s", exc)

        if payload_executors:
            return payload_executors
        if state_executors:
            return state_executors
        return []

    def get_executor(self, executor_id: str | None = None) -> dict[str, Any]:
        if not self.latest_payload or not self.latest_payload.get("executors"):
            raise RuntimeError("No executor information available. Request SSH access first.")

        executors = self.latest_payload.get("executors", [])
        if executor_id:
            for executor in executors:
                if executor.get("uuid") == executor_id:
                    return executor
            raise RuntimeError("Executor not found for the provided id")

        if not executors:
            raise RuntimeError("No executors available")

        return executors[0]

    async def detect_hardware(self) -> RunState:
        private_key_path = self.state.private_key_path or self._last_generated_keypair[0]
        if not private_key_path or not Path(private_key_path).exists():
            raise RuntimeError("Private key not found. Request SSH access first.")

        async with self._lock:
            if self._current_task and not self._current_task.done():
                raise RuntimeError("An SSH request is already running")

            executor = self.get_executor()
            host = executor.get("address")
            port = int(executor.get("ssh_port", 22))
            username = executor.get("ssh_username", "root")

            key_data = Path(private_key_path).read_text()
            pkey = asyncssh.import_private_key(key_data)

            commands = {
                "uname": "uname -a",
                "cpu": "lscpu",
                "memory": "free -m",
                "gpu_text": "nvidia-smi -L 2>/dev/null",
                "gpu_detail": "nvidia-smi 2>/dev/null",
            }

            self._update_state(message="Detecting executor hardware", status="hardware_check")

            results: dict[str, str] = {}

            try:
                async with asyncssh.connect(
                    host=host,
                    port=port,
                    username=username,
                    client_keys=[pkey],
                    known_hosts=None,
                ) as conn:
                    for key, command in commands.items():
                        try:
                            proc = await conn.run(command, check=False)
                            output = proc.stdout.strip() or proc.stderr.strip()
                            results[key] = output
                        except Exception as cmd_exc:  # pragma: no cover
                            results[key] = f"Command failed: {cmd_exc}"
            except Exception as exc:
                self._update_state(
                    status="error",
                    message="Hardware detection failed",
                    last_error=str(exc),
                    finished_at=time.time(),
                )
                raise

            executor_report = {**executor, "hardware_report": results}
            self.latest_payload = {
                **self.latest_payload,
                "executors": [executor_report],
            }

            if self.accept_path:
                self.accept_path.write_text(json.dumps(self.latest_payload, indent=2))

            self._update_state(
                status="hardware_collected",
                message="Hardware data collected",
                executor_count=1,
                executors=[executor_report],
                accept_payload_path=str(self.accept_path) if self.accept_path else None,
                last_error=None,
                finished_at=time.time(),
            )

            await self.refresh_containers(use_lock=False, silent=True)

            return self.state

    async def verify_quote(self, executor_id: str | None = None) -> dict[str, Any]:
        executor = self.get_executor(executor_id)
        executor_uuid = executor.get("uuid") or "unknown"
        report_data_hex, nonce_bytes = _generate_report_data()
        nonce_hex = nonce_bytes.hex()

        private_key_path = self.state.private_key_path or self._last_generated_keypair[0]
        if not private_key_path or not Path(private_key_path).exists():
            raise RuntimeError("Private key not available. Request SSH access first.")

        key_data = Path(private_key_path).read_text()
        try:
            pkey = asyncssh.import_private_key(key_data)
        except Exception as exc:  # pragma: no cover - defensive
            raise RuntimeError(f"Failed to load SSH key: {exc}") from exc

        host = executor.get("address")
        port = int(executor.get("ssh_port") or executor.get("port") or 22)
        username = executor.get("ssh_username") or "root"

        result: dict[str, Any] = {
            "executor_uuid": executor_uuid,
            "executor_address": host,
            "executor_port": port,
            "nonce": nonce_hex,
            "report_data": report_data_hex,
            "requested_at": time.time(),
        }

        self._update_state(
            verification_status="running",
            verification_message=f"Requesting quote from {executor_uuid}",
            verification_result=result,
        )
        remote_command = (
            f"docker run --rm -v {self.dstack_socket}:{self.dstack_socket} "
            f"alpine/curl --unix-socket {self.dstack_socket} "
            f"http://local/GetQuote?report_data={report_data_hex} 2>/dev/null"
        )

        try:
            try:
                async with asyncssh.connect(
                    host=host,
                    port=port,
                    username=username,
                    client_keys=[pkey],
                    known_hosts=None,
                ) as conn:
                    self._update_state(
                        verification_status="running",
                        verification_message=f"Fetching quote via {host}:{port}",
                        verification_result=result,
                    )
                    process = await conn.run(
                        remote_command,
                        check=False,
                        timeout=self.quote_timeout,
                        encoding=None,
                    )
            except asyncio.TimeoutError as exc:
                raise RuntimeError(
                    f"Fetching quote timed out after {self.quote_timeout:.0f}s"
                ) from exc
            except (asyncssh.Error, OSError) as exc:
                raise RuntimeError(f"Failed to run remote quote command: {exc}") from exc

            if process.exit_status != 0:
                stderr_text = (process.stderr or b"").decode("utf-8", errors="ignore").strip()
                stdout_text = (process.stdout or b"").decode("utf-8", errors="ignore").strip()
                error_text = stderr_text or stdout_text or f"exit code {process.exit_status}"
                raise RuntimeError(f"Failed to fetch quote: {error_text}")

            quote_response = (process.stdout or b"").strip()
            if not quote_response:
                raise RuntimeError("Quote response was empty")

            try:
                quote_json_text = quote_response.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise RuntimeError("Quote response is not valid UTF-8 text") from exc

            quote_json_text = quote_json_text.strip()
            if not quote_json_text:
                raise RuntimeError("Quote response contained only whitespace")

            try:
                verifier_response = await self._call_verifier(quote_json_text)
            except Exception as exc:
                raise RuntimeError(f"Quote verification failed: {exc}") from exc

            details_raw = verifier_response.get("details")
            details = details_raw if isinstance(details_raw, dict) else {}

            app_info_raw = details.get("app_info")
            app_info = app_info_raw if isinstance(app_info_raw, dict) else {}

            quote_verified = bool(details.get("quote_verified"))
            event_log_verified = bool(details.get("event_log_verified"))
            os_image_verified = bool(
                details.get("os_image_verified")
                or details.get("os_image_hash_verified")
            )

            os_image_hash = (
                (app_info.get("os_image_hash") if isinstance(app_info, dict) else None)
                or details.get("os_image_hash")
            )

            report_data_returned = details.get("report_data")

            try:
                expected_report_bytes = bytes.fromhex(report_data_hex)
            except ValueError:  # pragma: no cover - defensive, generated locally
                expected_report_bytes = None

            returned_report_bytes: bytes | None = None
            if isinstance(report_data_returned, str):
                token = report_data_returned.strip().lower()
                try:
                    returned_report_bytes = bytes.fromhex(token)
                except ValueError:
                    returned_report_bytes = None

            def _report_data_matches(
                expected: bytes | None,
                returned: bytes | None,
            ) -> bool:
                if expected is None or returned is None:
                    return False
                if returned == expected:
                    return True
                if len(returned) >= len(expected):
                    prefix = returned[: len(expected)]
                    suffix = returned[len(expected) :]
                    if prefix == expected and all(byte == 0 for byte in suffix):
                        return True
                return False

            report_data_verified = _report_data_matches(
                expected_report_bytes,
                returned_report_bytes,
            )

            advisories_raw = details.get("advisory_ids")
            if isinstance(advisories_raw, list):
                advisories = [entry for entry in advisories_raw if isinstance(entry, str)]
            elif isinstance(advisories_raw, str):
                advisories = [advisories_raw]
            else:
                advisories = []

            status_raw = details.get("tcb_status")
            tcb_status = status_raw.strip() if isinstance(status_raw, str) else None

            reason_raw = verifier_response.get("reason")
            reason = reason_raw.strip() if isinstance(reason_raw, str) else None
            is_valid = bool(verifier_response.get("is_valid"))

            if not report_data_verified:
                is_valid = False
                mismatch_reason = "Verifier report_data mismatch"
                if isinstance(report_data_returned, str) and report_data_returned:
                    mismatch_reason = (
                        f"{mismatch_reason}: expected {report_data_hex}, "
                        f"got {report_data_returned}"
                    )
                elif report_data_returned is None:
                    mismatch_reason = f"{mismatch_reason}: verifier omitted report_data"
                else:
                    mismatch_reason = (
                        f"{mismatch_reason}: verifier report_data not parseable"
                    )
                reason = mismatch_reason if not reason else f"{reason}; {mismatch_reason}"

            status_label = tcb_status or ("valid" if is_valid else "error")

            result.update(
                {
                    "verification_status": status_label,
                    "advisory_ids": advisories,
                    "verification_report": verifier_response,
                    "verifier_details": details,
                    "verifier_is_valid": is_valid,
                    "verifier_reason": reason,
                    "verifier_checks": {
                        "overall_valid": is_valid,
                        "quote_verified": quote_verified,
                        "event_log_verified": event_log_verified,
                        "os_image_verified": os_image_verified,
                        "report_data_verified": report_data_verified,
                        "tcb_status": tcb_status or ("valid" if is_valid else "unknown"),
                    },
                    "app_info": app_info,
                    "compose_hash": app_info.get("compose_hash"),
                    "report_data_returned": report_data_returned,
                    "report_data_verified": report_data_verified,
                    "os_image_hash": os_image_hash,
                    "verified_at": time.time(),
                }
            )

            if is_valid:
                result.pop("error", None)
            elif reason:
                result["error"] = reason

            updated_executors = self._update_executor_verification(executor_uuid, result)

            state_status = "success" if is_valid else "error"
            message_prefix = "Quote verification passed" if is_valid else "Quote verification failed"
            message = (
                f"{message_prefix} ({status_label})" if status_label else message_prefix
            )

            self._update_state(
                verification_status=state_status,
                verification_message=message,
                verification_result=result,
                executors=updated_executors or self.state.executors,
                executor_count=len(updated_executors) or self.state.executor_count,
                last_error=None if is_valid else (reason or status_label),
            )

            return result
        except Exception as exc:
            result.setdefault("error", str(exc))
            result.setdefault("traceback", traceback.format_exc())
            updated_executors = self._update_executor_verification(executor_uuid, result)
            self._update_state(
                verification_status="error",
                verification_message=str(exc),
                verification_result=result,
                executors=updated_executors or self.state.executors,
                executor_count=len(updated_executors) or self.state.executor_count,
                last_error=str(exc),
            )
            raise

    async def deploy_compose(
        self,
        compose_yaml: str,
        project_name: str | None = None,
        executor_id: str | None = None,
    ) -> RunState:
        if not compose_yaml or not compose_yaml.strip():
            raise RuntimeError("Compose content is empty")

        target_executor = self.get_executor(executor_id)

        private_key_path = self.state.private_key_path or self._last_generated_keypair[0]
        if not private_key_path or not Path(private_key_path).exists():
            raise RuntimeError("Private key not found. Request SSH access first.")

        project = project_name.strip() if project_name else f"mock-project-{int(time.time())}"
        timestamp = time.time()
        remote_dir = f"/tmp/mock-validator/{project}-{int(timestamp)}"

        async with self._lock:
            if self._current_task and not self._current_task.done():
                raise RuntimeError("Another SSH task is already running")

            self._update_state(
                status="deploying_compose",
                message=f"Deploying docker-compose project '{project}'",
                last_error=None,
            )

            self._current_task = asyncio.create_task(
                self._deploy_compose(
                    executor=target_executor,
                    private_key_path=private_key_path,
                    compose_yaml=compose_yaml,
                    project=project,
                    remote_dir=remote_dir,
                    timestamp=timestamp,
                )
            )

        return self.state

    async def _deploy_compose(
        self,
        executor: dict[str, Any],
        private_key_path: str,
        compose_yaml: str,
        project: str,
        remote_dir: str,
        timestamp: float,
    ) -> None:
        host = executor.get("address")
        port = int(executor.get("ssh_port", 22))
        username = executor.get("ssh_username", "root")
        compose_path = f"{remote_dir}/docker-compose.yml"

        entry = {
            "timestamp": timestamp,
            "project": project,
            "executor": f"{host}:{port}",
            "status": "in_progress",
            "message": "Deploying",
            "details": "",
            "remote_directory": remote_dir,
        }

        key_data = Path(private_key_path).read_text()
        pkey = asyncssh.import_private_key(key_data)

        try:
            async with asyncssh.connect(
                host=host,
                port=port,
                username=username,
                client_keys=[pkey],
                known_hosts=None,
            ) as conn:
                await conn.run(f"mkdir -p {remote_dir}", check=True)

                async with conn.start_sftp() as sftp:
                    async with sftp.open(compose_path, "w") as remote_file:
                        await remote_file.write(compose_yaml)

                command = f"cd {remote_dir} && docker compose -p {project} up -d"
                result = await conn.run(command, check=False)
                if result.exit_status != 0:
                    fallback_cmd = f"cd {remote_dir} && docker-compose -p {project} up -d"
                    result = await conn.run(fallback_cmd, check=False)
                    if result.exit_status != 0:
                        raise RuntimeError(result.stderr or result.stdout or "docker compose command failed")

                entry.update(
                    status="success",
                    message="Deployment succeeded",
                    details=result.stdout or result.stderr or "",
                )

        except Exception as exc:
            entry.update(status="error", message=str(exc))
            self.compose_history.insert(0, entry)
            self.compose_history = self.compose_history[:10]
            self._current_task = None
            self._update_state(
                status="error",
                message="Docker compose deployment failed",
                last_error=str(exc),
                compose_history=list(self.compose_history),
            )
            raise
        else:
            self.compose_history.insert(0, entry)
            self.compose_history = self.compose_history[:10]
            await self.refresh_containers(executor_id=executor.get("uuid"), use_lock=False, silent=True)
            self._update_state(
                status="compose_deployed",
                message=f"Docker compose deployed for '{project}'",
                last_error=None,
                finished_at=time.time(),
                compose_history=list(self.compose_history),
            )
        finally:
            self._current_task = None

    async def refresh_containers(
        self,
        executor_id: str | None = None,
        use_lock: bool = True,
        silent: bool = False,
    ) -> RunState:
        async def _refresh() -> RunState:
            private_key_path = self.state.private_key_path or self._last_generated_keypair[0]
            if not private_key_path or not Path(private_key_path).exists():
                raise RuntimeError("Private key not found. Request SSH access first.")

            target_executor = self.get_executor(executor_id)

            host = target_executor.get("address")
            port = int(target_executor.get("ssh_port", 22))
            username = target_executor.get("ssh_username", "root")

            key_data = Path(private_key_path).read_text()
            pkey = asyncssh.import_private_key(key_data)

            command = "docker ps --format '{{json .}}'"

            try:
                async with asyncssh.connect(
                    host=host,
                    port=port,
                    username=username,
                    client_keys=[pkey],
                    known_hosts=None,
                ) as conn:
                    result = await conn.run(command, check=False)
            except Exception as exc:
                if not silent:
                    self._update_state(
                        status="error",
                        message="Failed to refresh container list",
                        last_error=str(exc),
                    )
                raise
            else:
                if result.exit_status != 0:
                    raise RuntimeError(result.stderr or result.stdout or "docker ps failed")

                containers: list[dict[str, Any]] = []
                for line in result.stdout.splitlines():
                    try:
                        containers.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

                self.running_containers = containers
                self._update_state(
                    status=self.state.status,
                    message=self.state.message if silent else "Refreshed container list",
                    last_error=self.state.last_error,
                )
                return self.state

        if use_lock:
            async with self._lock:
                return await _refresh()
        return await _refresh()

    def state_dict(self) -> dict[str, Any]:
        return self.state.to_dict()


app = FastAPI(title="Mock Validator")
service: MockValidatorService | None = None


@app.on_event("startup")
async def startup() -> None:
    global service
    service = MockValidatorService()
    LOGGER.info("Mock validator service ready for miner %s:%s", service.miner_host, service.miner_port)


def render_index(state: RunState) -> str:
    state_json = json.dumps(state.to_dict())
    return HTML_TEMPLATE.replace('__STATE_JSON__', state_json)


@app.get("/", response_class=HTMLResponse)
async def index() -> HTMLResponse:
    if service is None:
        raise HTTPException(status_code=503, detail="Service not ready")
    return HTMLResponse(render_index(service.state))


@app.post("/rent")
async def rent(request: Request) -> JSONResponse:
    if service is None:
        raise HTTPException(status_code=503, detail="Service not ready")

    executor_id: str | None = None
    if request.headers.get("content-type", "").startswith("application/json"):
        payload = await request.json()
        executor_id = payload.get("executor_id") if isinstance(payload, dict) else None
    else:
        form = await request.form()
        executor_id = form.get("executor_id")

    try:
        state = await service.start_request(executor_id or None)
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc))

    return JSONResponse(state.to_dict())


@app.get("/status")
async def status() -> JSONResponse:
    if service is None:
        raise HTTPException(status_code=503, detail="Service not ready")
    return JSONResponse(service.state_dict())


@app.post("/verify_quote")
async def verify_quote_endpoint(request: Request) -> JSONResponse:
    if service is None:
        raise HTTPException(status_code=503, detail="Service not ready")

    executor_id: str | None = None
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            payload = await request.json()
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=400, detail=f"Invalid JSON: {exc}") from exc
        if isinstance(payload, dict):
            executor_id = payload.get("executor_id")
    else:
        executor_id = request.query_params.get("executor_id")

    try:
        verification = await service.verify_quote(executor_id or None)
    except RuntimeError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:  # pragma: no cover - surfaced to caller
        raise HTTPException(status_code=502, detail=str(exc))

    response_payload = {
        "verification": verification,
        "state": service.state.to_dict(),
    }
    return JSONResponse(response_payload)


@app.post("/detect_hardware")
async def detect_hardware_endpoint() -> JSONResponse:
    if service is None:
        raise HTTPException(status_code=503, detail="Service not ready")

    try:
        state = await service.detect_hardware()
    except RuntimeError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:  # pragma: no cover - surfaced to caller
        raise HTTPException(status_code=502, detail=str(exc))

    return JSONResponse(state.to_dict())


@app.post("/deploy_compose")
async def deploy_compose_endpoint(request: Request) -> JSONResponse:
    if service is None:
        raise HTTPException(status_code=503, detail="Service not ready")

    payload = await request.json()
    compose_yaml = payload.get("compose_yaml") if isinstance(payload, dict) else None
    project_name = payload.get("project_name") if isinstance(payload, dict) else None
    executor_id = payload.get("executor_id") if isinstance(payload, dict) else None

    if not compose_yaml or not compose_yaml.strip():
        raise HTTPException(status_code=400, detail="compose_yaml is required")

    try:
        state = await service.deploy_compose(compose_yaml, project_name, executor_id)
    except RuntimeError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:  # pragma: no cover - surfaced to caller
        raise HTTPException(status_code=502, detail=str(exc))

    return JSONResponse(state.to_dict())


@app.post("/refresh_containers")
async def refresh_containers_endpoint(request: Request) -> JSONResponse:
    if service is None:
        raise HTTPException(status_code=503, detail="Service not ready")

    payload = await request.json() if request.headers.get("content-type") == "application/json" else {}
    executor_id = payload.get("executor_id") if isinstance(payload, dict) else None

    try:
        state = await service.refresh_containers(executor_id=executor_id)
    except RuntimeError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:  # pragma: no cover - surfaced to caller
        raise HTTPException(status_code=502, detail=str(exc))

    return JSONResponse(state.to_dict())


@app.websocket("/ws/ssh/{executor_uuid}")
async def ssh_terminal(websocket: WebSocket, executor_uuid: str):
    if service is None:
        await websocket.close(code=1011, reason="Service not ready")
        return

    await websocket.accept()

    try:
        executor = service.get_executor(executor_uuid)
        private_key_path = service.state.private_key_path or service._last_generated_keypair[0]
        if not private_key_path or not Path(private_key_path).exists():
            raise RuntimeError("Private key not available. Request SSH access first.")

        key_data = Path(private_key_path).read_text()
        pkey = asyncssh.import_private_key(key_data)

        host = executor.get("address")
        ssh_port = int(executor.get("ssh_port") or executor.get("port") or 22)
        username = executor.get("ssh_username") or "root"

        conn = await asyncssh.connect(
            host=host,
            port=ssh_port,
            username=username,
            client_keys=[pkey],
            known_hosts=None,
        )
        process = await conn.create_process(term_type="xterm-256color", term_size=(120, 32))
    except Exception as exc:
        try:
            await websocket.send_text(f"[error] {exc}\n")
        finally:
            await websocket.close(code=1011)
        return

    async def pump(stream):
        try:
            async for data in stream:
                if data:
                    await websocket.send_text(data)
        except Exception:
            pass

    stdout_task = asyncio.create_task(pump(process.stdout))
    stderr_task = asyncio.create_task(pump(process.stderr))

    try:
        while True:
            try:
                message = await websocket.receive_text()
            except WebSocketDisconnect:
                break
            except Exception:
                break

            if message is None:
                continue

            try:
                process.stdin.write(message)
                try:
                    await process.stdin.drain()
                except Exception:
                    pass
            except Exception:
                break
    finally:
        stdout_task.cancel()
        stderr_task.cancel()
        await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)
        try:
            process.stdin.close()
        except Exception:
            pass
        try:
            await process.wait_closed()
        except Exception:
            pass
        conn.close()
        try:
            await conn.wait_closed()
        except Exception:
            pass


@app.get("/result")
async def result() -> JSONResponse:
    if service is None:
        raise HTTPException(status_code=503, detail="Service not ready")
    if not service.latest_payload:
        raise HTTPException(status_code=404, detail="No result recorded yet")
    return JSONResponse(service.latest_payload)


@app.get("/accept")
async def accept_payload() -> FileResponse:
    if service is None:
        raise HTTPException(status_code=503, detail="Service not ready")
    if not service.accept_path.exists():
        raise HTTPException(status_code=404, detail="Accept payload not found")
    return FileResponse(service.accept_path)
