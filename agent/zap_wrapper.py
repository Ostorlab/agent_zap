"""Zap wrapper implementation"""
import json
import logging
import pathlib
import subprocess
import tempfile
from typing import List, Dict

logger = logging.getLogger(__name__)

PROFILE_SCRIPT = {
    'baseline': '/zap/zap-baseline.py',
    'api': '/zap/zap-api.py',
    'full': '/zap/zap-full-scan.py',

}


class ZapWrapper:
    """Zap scanner wrapper."""

    def __init__(self, scan_profile: str):
        """Configures wrapper to start scanning targets.

        Args:
            scan_profile: Scan profile from one of these values (baseline, api and full).
        """
        if scan_profile not in PROFILE_SCRIPT.keys():
            raise ValueError()
        self._scan_profile = scan_profile

    def scan(self, target: str) -> Dict:
        """Starts a scan on targets and returns JSON generated output.

        Args:
            target: Target URL.

        Returns:
            JSON generated output as a dict.
        """
        with tempfile.NamedTemporaryFile(dir='/zap/wrk', suffix='.json') as t:
            command = self._prepare_command(target, pathlib.Path(t.name).name)
            logger.info('running command %s', command)
            subprocess.run(command)
            return json.load(t)

    def _prepare_command(self, url: str, output) -> List[str]:
        """Prepare zap command."""
        return [PROFILE_SCRIPT[self._scan_profile], '-d', '-t', url, '-j', '-J', output]
