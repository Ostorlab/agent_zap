"""Zap agent implementation"""
import logging
from typing import Dict

from ostorlab.agent import agent
from ostorlab.agent import message as m
from ostorlab.agent.mixins import agent_report_vulnerability_mixin as vuln_mixin
from rich import logging as rich_logging

from agent import result_parser
from agent import zap_wrapper

logging.basicConfig(
    format='%(message)s',
    datefmt='[%X]',
    handlers=[rich_logging.RichHandler(rich_tracebacks=True)]
)
logger = logging.getLogger(__name__)
logger.setLevel('DEBUG')


class ZapAgent(agent.Agent, vuln_mixin.AgentReportVulnMixin):
    """Zap open-source web scanner agent."""

    _scan_profile: str

    def start(self) -> None:
        """Setup Zap scanner."""
        self._zap = zap_wrapper.ZapWrapper(scan_profile=self.args.get('scan_profile'))

    def process(self, message: m.Message) -> None:
        """Trigger zap scan and emits vulnerabilities.

        Args:
            message: target scan message.

        Returns:
            None
        """
        target = self._prepare_target(message)
        logger.info('scanning target %s', target)
        results = self._zap.scan(target)
        self._emit_results(results)

    def _prepare_target(self, message: m.Message) -> str:
        """Prepare targets based on type, if a domain name is provided, port and protocol are collected from the config.
        """
        domain_name = message.data.get('name')
        https = self.args.get('https')
        port = self.args.get('port')
        if https and port != 443:
            return f'https://{domain_name}:{port}'
        elif https:
            return f'https://{domain_name}'
        elif port == 80:
            return f'http://{domain_name}'
        else:
            return f'http://{domain_name}:{port}'

    def _emit_results(self, results: Dict) -> None:
        """Parses results and emits vulnerabilities."""
        for vuln in result_parser.parse_results(results):
            self.report_vulnerability(
                entry=vuln.entry,
                technical_detail=vuln.technical_detail,
                risk_rating=vuln.risk_rating)


if __name__ == '__main__':
    logger.info('starting agent ...')
    ZapAgent.main()
