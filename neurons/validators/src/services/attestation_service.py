import hashlib
import logging
from typing import Optional

import aiohttp
import asyncssh

from datura.requests.miner_requests import ExecutorSSHInfo

from core.config import settings
from core.utils import _m, get_extra_info

logger = logging.getLogger(__name__)


class AttestationError(RuntimeError):
    """Raised when attestation or host verification fails."""


class AttestationService:
    """
    Validates executor authenticity for Intel TDX deployments by verifying a pre-generated
    quote supplied alongside the executor's SSH host key.

    If attestation is disabled (default), this service becomes a no-op and simply returns
    the host key policy when possible.
    """

    REPORT_PREFIX = b"SSH_HOST_KEY:"

    def __init__(self) -> None:
        self.enabled: bool = bool(
            settings.ENABLE_TDX_ATTESTATION and settings.TDX_VERIFIER_URL)
        self.verifier_url: Optional[str] = settings.TDX_VERIFIER_URL
        self.quote_timeout: int = 60

    def _should_verify(self, executor: ExecutorSSHInfo) -> bool:
        return self.enabled and bool(executor.tdx_quote)

    def _expected_report_data(self, host_key: str) -> str:
        digest = hashlib.sha256(self.REPORT_PREFIX +
                                host_key.encode("utf-8")).hexdigest()
        return f"0x{digest}"

    async def _call_verifier(self, quote_json: str, executor: ExecutorSSHInfo) -> dict:
        if not self.verifier_url:
            raise AttestationError("TDX verifier URL is not configured")

        url = self.verifier_url.rstrip("/")
        if not url.endswith("/verify"):
            url = f"{url}/verify"

        logger.info(f"[VERIFIER REQUEST] Posting to {url} for {executor.address}:{executor.port}")

        timeout = aiohttp.ClientTimeout(total=self.quote_timeout)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(
                url,
                data=quote_json.encode("utf-8"),
                headers={"Content-Type": "application/json"},
            ) as response:
                if response.status >= 400:
                    snippet = await response.text()
                    snippet = snippet[:200] if snippet else "<empty>"
                    raise AttestationError(
                        f"Verifier request returned {response.status} for executor {executor.address}:{executor.port}: {snippet}"
                    )
                try:
                    return await response.json()
                except aiohttp.ContentTypeError as exc:
                    raise AttestationError(
                        "Verifier response was not JSON") from exc

    @staticmethod
    def _normalise_report_data(value: Optional[str]) -> Optional[bytes]:
        if not value:
            return None
        token = value.strip().lower()
        if token.startswith("0x"):
            token = token[2:]
        try:
            return bytes.fromhex(token)
        except ValueError:
            return None

    def _validate_verifier_response(self, verifier_payload: dict, expected_report_hex: str, executor: ExecutorSSHInfo) -> None:
        details = verifier_payload.get("details")
        if not isinstance(details, dict):
            raise AttestationError(
                "Verifier response missing details section")

        is_valid = bool(verifier_payload.get("is_valid"))
        quote_verified = bool(details.get("quote_verified"))
        # TODO: check more fields

        expected_bytes = self._normalise_report_data(expected_report_hex)
        returned_bytes = self._normalise_report_data(
            details.get("report_data"))
        report_matches = (
            expected_bytes is not None
            and returned_bytes is not None
            and returned_bytes.startswith(expected_bytes)
        )

        if not (is_valid and quote_verified and report_matches):
            raise AttestationError(
                f"Verifier rejected TDX quote for executor {executor.address}:{executor.port}"
            )

    async def prepare_host_policy(
        self,
        executor: ExecutorSSHInfo,
        miner_hotkey: Optional[str],
    ) -> Optional[asyncssh.SSHKnownHosts]:
        should_verify = self._should_verify(executor)

        if not executor.ssh_host_key:
            if should_verify:
                raise AttestationError(
                    f"Executor {executor.address}:{executor.port} missing SSH host key for attestation"
                )
            return None

        if should_verify:
            quote = executor.tdx_quote
            if not isinstance(quote, str) or not quote.strip():
                raise AttestationError(
                    f"Executor {executor.address}:{executor.port} provided empty TDX quote"
                )

            expected_report = self._expected_report_data(executor.ssh_host_key)
            verifier_payload = await self._call_verifier(quote.strip(), executor)
            self._validate_verifier_response(
                verifier_payload, expected_report, executor)
            logger.info(
                _m(
                    "TDX quote verified",
                    extra=get_extra_info(
                        {"executor": f"{executor.address}:{executor.port}"}),
                )
            )

        hosts = [executor.address]
        try:
            port = int(executor.port)
        except Exception:  # pragma: no cover - defensive
            port = None
        if port:
            hosts.append(f"[{executor.address}]:{port}")

        known_hosts_entry = ",".join(hosts)

        try:
            return asyncssh.import_known_hosts(
                f"{known_hosts_entry} {executor.ssh_host_key.strip()}\n"
            )
        except Exception as exc:
            logger.warning(
                _m(
                    "Failed to build executor known_hosts entry",
                    extra=get_extra_info(
                        {
                            "executor": f"{executor.address}:{executor.port}",
                            "error": str(exc),
                        }
                    ),
                )
            )
            return None
