"""Zap wrapper implementation"""
import json
import logging
import pathlib
import subprocess
import tempfile
import datetime
from typing import List, Dict


class Error(Exception):
    """Base Custom Error Class."""


class RunCommandError(Error):
    """Error when running a command using a subprocess."""


class SetUpVpnError(Error):
    """Set Up VPN Error."""


RESOLV_CONFIG_PATH = pathlib.Path("/app/agent/tools/wireguard/resolv/resolv.conf")
JAVA_COMMAND_TIMEOUT = datetime.timedelta(minutes=5)

logger = logging.getLogger(__name__)

OUTPUT_SUFFIX = ".json"
OUTPUT_DIR = "/zap/wrk"
PROFILE_SCRIPT = {
    "baseline": "/zap/zap-baseline.py",
    "api": "/zap/zap-api.py",
    "full": "/zap/zap-full-scan.py",
}


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
            subprocess.run(command, check=False)
            try:
                return json.load(t)
            except json.JSONDecodeError:
                return {}

    def _write_vpn_config_content_to_file(self, vpn_config_content: str) -> None:
        """Write the config content to a file
        Args:
            vpn_config_content: vpn config content
        """
        with open("/etc/wireguard/wg0.conf", "w", encoding="UTF-8") as config_file:
            config_file.write(vpn_config_content)

    def use_vpn(self, vpn_config_content: str) -> None:
        """Use the Vpn for the scan in case if the country code was set
        Args:
            vpn_config_content: the vpn config
        """
        if vpn_config_content is None or vpn_config_content == "":
            logger.error("No config file found for this country to setup the Vpn")
            raise SetUpVpnError

        self._write_vpn_config_content_to_file(vpn_config_content)

        self._exec_command(["wg-quick", "up", "wg0"])
        self._exec_command(["cp", str(RESOLV_CONFIG_PATH), "/etc/resolv.conf"])

        logger.info("connected with %s", RESOLV_CONFIG_PATH)

    def _exec_command(self, command: List[str]) -> None:
        """Execute a command.

        Args:
            command: The command to execute.
        """
        try:
            logger.info("%s", " ".join(command))
            output = subprocess.run(
                command,
                capture_output=True,
                timeout=JAVA_COMMAND_TIMEOUT.seconds,
                check=True,
            )
            logger.debug("process returned: %s", output.returncode)
            logger.debug("output: %s", output.stdout)
            logger.debug("err: %s", output.stderr)

        except subprocess.CalledProcessError as e:
            raise RunCommandError(
                f'An error occurred while running the command {" ".join(command)}'
            ) from e
        except subprocess.TimeoutExpired:
            logger.warning("Java command timed out for command %s", " ".join(command))

    def _prepare_command(self, url: str, output) -> List[str]:
        """Prepare zap command."""
        return [PROFILE_SCRIPT[self._scan_profile], "-d", "-t", url, "-j", "-J", output]
