"""Zap wrapper implementation"""
import datetime
import json
import logging
import pathlib
import subprocess
import tempfile
from typing import List, Dict

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


class ZapWrapper:
    """Zap scanner wrapper."""

    def __init__(self, scan_profile: str):
        """Configures wrapper to start scanning targets.

        Args:
            scan_profile: Scan profile from one of these values (baseline, api and full).
        """
        if scan_profile not in PROFILE_SCRIPT:
            raise ValueError()
        self._scan_profile = scan_profile

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
        return [PROFILE_SCRIPT[self._scan_profile], "-d", "-t", url, "-j", "-J", output]
