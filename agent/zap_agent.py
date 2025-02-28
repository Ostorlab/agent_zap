"""Zap agent implementation"""

import datetime
import logging
import re
import subprocess
from typing import cast

from ostorlab.agent import agent, definitions as agent_definitions
from ostorlab.agent.message import message as m
from ostorlab.agent.mixins import agent_report_vulnerability_mixin as vuln_mixin
from ostorlab.runtimes import definitions as runtime_definitions
from rich import logging as rich_logging

from agent import helpers
from agent import result_parser
from agent import zap_wrapper


class Error(Exception):
    """Base Custom Error Class."""


class RunCommandError(Error):
    """Error when running a command using a subprocess."""


class SetUpVpnError(Error):
    """Set Up VPN Error."""


COMMAND_TIMEOUT = datetime.timedelta(minutes=1)

WIREGUARD_CONFIG_FILE_PATH = "/etc/wireguard/wg0.conf"
DNS_RESOLV_CONFIG_PATH = "/etc/resolv.conf"

logging.basicConfig(
    format="%(message)s",
    datefmt="[%X]",
    handlers=[rich_logging.RichHandler(rich_tracebacks=True)],
    level="INFO",
    force=True,
)
logger = logging.getLogger(__name__)


class ZapAgent(agent.Agent, vuln_mixin.AgentReportVulnMixin):
    """Zap open-source web scanner agent."""

    _scan_profile: str

    def __init__(
        self,
        agent_definition: agent_definitions.AgentDefinition,
        agent_settings: runtime_definitions.AgentSettings,
    ) -> None:
        agent.Agent.__init__(self, agent_definition, agent_settings)
        vuln_mixin.AgentReportVulnMixin.__init__(self)
        self._scope_urls_regex: str | None = self.args.get("scope_urls_regex")
        self._vpn_config_content: str | None = self.args.get("vpn_config")
        self._vpn_dns_content: str | None = self.args.get("dns_config")
        self._scan_profile: str | None = self.args.get("scan_profile")
        self._crawl_timeout: int | None = self.args.get("crawl_timeout")
        self._proxy: str | None = self.args.get("proxy")

    def start(self) -> None:
        """Setup Zap scanner."""
        self._zap = zap_wrapper.ZapWrapper(
            scan_profile=self._scan_profile,
            crawl_timeout=self._crawl_timeout,
            proxy=self._proxy,
        )

    def process(self, message: m.Message) -> None:
        """Trigger zap scan and emits vulnerabilities.

        Args:
            message: target scan message.

        Returns:
            None
        """

        if self._vpn_config_content is not None:
            try:
                self.use_vpn(self._vpn_config_content)
            except SetUpVpnError:
                logger.error("Can't set the status of Vpn action")

        target = self._prepare_target(message)
        if self._should_process_target(self._scope_urls_regex, target) is False:
            logger.info("scanning target does not match url regex %s", target)
        else:
            logger.info("scanning target %s", target)

            results = self._zap.scan(target)
            self._emit_results(results)

    def _prepare_target(self, message: m.Message) -> str:
        """Prepare targets based on type,
        if a domain name is provided, port and protocol are collected from the config.
        """
        if message.data.get("name") is not None:
            domain_name = message.data.get("name")
            https = self.args.get("https")
            port = self.args.get("port")
            if https is True and port != 443:
                return f"https://{domain_name}:{port}"
            elif https is True:
                return f"https://{domain_name}"
            elif port == 80:
                return f"http://{domain_name}"
            else:
                return f"http://{domain_name}:{port}"
        elif message.data.get("url") is not None:
            return message.data.get("url")

    def _emit_results(self, results: dict) -> None:
        """Parses results and emits vulnerabilities."""
        for vuln in result_parser.parse_results(results):
            dna = helpers.compute_dna(
                vulnerability_title=vuln.entry.title,
                vuln_location=vuln.vulnerability_location,
                technical_detail=vuln.technical_detail
            )
            self.report_vulnerability(
                entry=vuln.entry,
                technical_detail=vuln.technical_detail,
                risk_rating=vuln.risk_rating,
                vulnerability_location=vuln.vulnerability_location,
            )

    def _should_process_target(self, scope_urls_regex: str | None, url: str) -> bool:
        if scope_urls_regex is None:
            return True
        link_in_scan_domain = re.match(scope_urls_regex, url) is not None
        if not link_in_scan_domain:
            logger.warning("link url %s is not in domain %s", url, scope_urls_regex)
        return link_in_scan_domain

    def use_vpn(self, vpn_config_content: str) -> None:
        """Use the Vpn for the scan in case if the country code was set
        Args:
            vpn_config_content: the vpn config
        """
        try:
            if vpn_config_content is None or vpn_config_content == "":
                logger.error("No config file found for this country to setup the Vpn")
                raise SetUpVpnError

            self._save_vpn_and_dns_configurations()

            self._exec_command(["wg-quick", "up", "wg0"])

            logger.info("connected with %s", DNS_RESOLV_CONFIG_PATH)
        except RunCommandError as e:
            logger.warning("%s", e)

    def _save_vpn_and_dns_configurations(self) -> None:
        """Write the config content to a file
        Args:
            vpn_config_content: vpn config content
        """
        logger.info("writing congif")
        with open(WIREGUARD_CONFIG_FILE_PATH, "w", encoding="UTF-8") as conf_file:
            conf_file.write(cast(str, self._vpn_config_content))

        with open(DNS_RESOLV_CONFIG_PATH, "w", encoding="UTF-8") as dns_file:
            dns_file.write(cast(str, self._vpn_dns_content))

    def _exec_command(self, command: list[str]) -> None:
        """Execute a command.

        Args:
            command: The command to execute.
        """
        try:
            logger.info("%s", " ".join(command))
            output = subprocess.run(
                command,
                capture_output=True,
                timeout=COMMAND_TIMEOUT.seconds,
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


if __name__ == "__main__":
    logger.info("starting agent ...")
    ZapAgent.main()
