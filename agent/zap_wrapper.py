"""Zap wrapper implementation"""
import datetime
import json
import logging
import pathlib
import subprocess
import tempfile
from typing import List, Dict, NamedTuple
from urllib import parse

import tenacity

logger = logging.getLogger(__name__)

OUTPUT_SUFFIX = ".json"
OUTPUT_DIR = "/zap/wrk"
PROFILE_SCRIPT = {
    "baseline": "/zap/zap-baseline.py",
    "api": "/zap/zap-api.py",
    "full": "/zap/zap-full-scan.py",
}

JAVA_COMMAND_TIMEOUT = datetime.timedelta(minutes=60)

ProxyTuple = NamedTuple("ProxyTuple", [("proxy_host", str), ("proxy_port", str)])


def _parse_proxy(proxy: str) -> ProxyTuple | None:
    """Get proxy arguments."""
    parsed_url = parse.urlparse(proxy)
    if parsed_url.port is not None and parsed_url.hostname is not None:
        return ProxyTuple(parsed_url.hostname, str(parsed_url.port))
    logger.warning("Invalid proxy URL: %s", proxy)
    return None


class ZapWrapper:
    """Zap scanner wrapper."""

    def __init__(
        self,
        scan_profile: str,
        crawl_timeout: int | None = None,
        proxy: str | None = None,
    ) -> None:
        """Configures wrapper to start scanning targets.

        Args:
            scan_profile: Scan profile from one of these values (baseline, api and full).
            crawl_timeout: Max duration to crawl in minutes. None means no limit.
        """
        if scan_profile not in PROFILE_SCRIPT:
            raise ValueError()
        self._scan_profile = scan_profile
        self._crawl_timeout = crawl_timeout
        self._proxy = proxy

    @tenacity.retry(
        stop=tenacity.stop_after_attempt(5),
        wait=tenacity.wait_fixed(2),
        retry=tenacity.retry_if_exception_type(subprocess.TimeoutExpired),
    )
    def scan(self, target: str) -> Dict:
        """Starts a scan on targets and returns JSON generated output.

        Args:
            target: Target URL.

        Returns:
            JSON generated output as a dict.
        """
        with tempfile.NamedTemporaryFile(dir=OUTPUT_DIR, suffix=OUTPUT_SUFFIX) as t:
            command = self._prepare_command(target, pathlib.Path(t.name).name)
            logger.info("running command %s", command)
            try:
                subprocess.run(
                    command, check=False, timeout=JAVA_COMMAND_TIMEOUT.seconds
                )
                return json.load(t)
            except json.JSONDecodeError:
                return {}

    def _prepare_command(self, url: str, output) -> List[str]:
        """Prepare zap command."""
        command = [PROFILE_SCRIPT[self._scan_profile], "-d"]
        # Set target.
        command += ["-t", url]
        # Set timeout.
        if self._crawl_timeout is not None:
            command.extend(["-m", str(self._crawl_timeout)])
        # Set proxy.
        if self._proxy is not None:
            parsed_proxy = _parse_proxy(self._proxy)
            if parsed_proxy is not None:
                zap_arguments = (
                    f"-config network.connection.httpProxy.enabled=true -config network.connection.httpProxy.host={parsed_proxy.proxy_host} -config network.connection.httpProxy.port={parsed_proxy.proxy_port}"
                )
                # Note: zap_arguments is a STRING,
                # and it passed as a single argument to the command, using the -z option for the zap profile.
                command.extend(["-z", f'"{zap_arguments}"'])
        # Set output and Spider crawling.
        command.extend(["-j", "-J", output])
        return command
