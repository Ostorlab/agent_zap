"""Zap agent implementation"""
import logging
from typing import Dict, Optional
import re

from ostorlab.agent import agent, definitions as agent_definitions
from ostorlab.agent.message import message as m
from ostorlab.agent.mixins import agent_report_vulnerability_mixin as vuln_mixin
from ostorlab.runtimes import definitions as runtime_definitions

from rich import logging as rich_logging

from agent import result_parser
from agent import zap_wrapper

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
        self._scope_urls_regex: Optional[str] = self.args.get("scope_urls_regex")

    def start(self) -> None:
        """Setup Zap scanner."""
        self._zap = zap_wrapper.ZapWrapper(scan_profile=self.args.get("scan_profile"))

    def process(self, message: m.Message) -> None:
        """Trigger zap scan and emits vulnerabilities.

        Args:
            message: target scan message.

        Returns:
            None
        """
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

    def _emit_results(self, results: Dict) -> None:
        """Parses results and emits vulnerabilities."""
        for vuln in result_parser.parse_results(results):
            self.report_vulnerability(
                entry=vuln.entry,
                technical_detail=vuln.technical_detail,
                risk_rating=vuln.risk_rating,
                vulnerability_location=vuln.vulnerability_location,
            )

    def _should_process_target(self, scope_urls_regex: Optional[str], url: str) -> bool:
        if scope_urls_regex is None:
            return True
        link_in_scan_domain = re.match(scope_urls_regex, url) is not None
        if not link_in_scan_domain:
            logger.warning("link url %s is not in domain %s", url, scope_urls_regex)
        return link_in_scan_domain


if __name__ == "__main__":
    logger.info("starting agent ...")
    ZapAgent.main()
