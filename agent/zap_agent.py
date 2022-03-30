"""Zap agent implementation"""
import io
import json
import logging
import pathlib
import subprocess
import tempfile
from typing import List

from ostorlab.agent.kb import kb
from ostorlab.agent import agent
from ostorlab.agent.mixins import agent_report_vulnerability_mixin
from ostorlab.agent import message as m
from rich import logging as rich_logging

logging.basicConfig(
    format='%(message)s',
    datefmt='[%X]',
    handlers=[rich_logging.RichHandler(rich_tracebacks=True)]
)
logger = logging.getLogger(__name__)
logger.setLevel('DEBUG')

PROFILE_SCRIPT = {
    'baseline': '/zap/zap-baseline.py'
}

RISK_RATING_MAPPING = {
    1: 'HIGH'
}


class ZapAgent(agent.Agent, agent_report_vulnerability_mixin.AgentReportVulnMixin):
    """Zap open-source web scanner agent."""

    _scan_profile: str

    def start(self) -> None:
        self._scan_profile = self.args.get('scan_profile')
        if self._scan_profile not in ['baseline', 'full', 'api']:
            raise ValueError()

    def process(self, message: m.Message) -> None:
        target = self._prepare_target(message)
        logger.info('scanning target %s', target)
        with tempfile.NamedTemporaryFile(dir='/zap/wrk', suffix='.json') as t:
            command = self._prepare_command(target, pathlib.Path(t.name).name)
            logger.info('running command %s', command)
            subprocess.run(command)
            self._emit_results(t)


    def _prepare_target(self, message: m.Message) -> str:
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

    def _prepare_command(self, url: str, output) -> List[str]:
        return [PROFILE_SCRIPT[self._scan_profile], '-d', '-t', url, '-j', '-J', output]

    def _emit_results(self, output: io.FileIO) -> None:
        result = json.load(output)
        for site in result.get('site', []):
            target = site.get('@name')
            for alert in site.get('alerts'):
                title = alert.get('name')
                description = alert.get('desc')
                recommendation = alert.get('solution')
                technical_detail_header = alert.get('otherinfo')
                risk_rating_id = alert.get('riskcode')
                risk_rating_confidence_id = alert.get('confidence')
                references = [r for r in alert.get('reference').split('</p>').replace('<p>', '') if r]
                cweid = alert.get('cweid')
                cweid = alert.get('cweid')
                wascid = alert.get('wascid')
                for instance in alert.get('instances'):
                    uri = instance.get('uri')
                    method = instance.get('method')
                    param = instance.get('param')
                    attack = instance.get('attack')
                    evidence = instance.get('evidence')

                self.report_vulnerability(
                    entry=kb.Entry(
                        title=title,
                        risk_rating=NUCLEI_RISK_MAPPING[severity].value,
                        short_description=description,
                        description=description,
                        recommendation=recommendation,
                        references=references,
                        security_issue=True,
                        privacy_issue=False,
                        has_public_exploit=False,
                        targeted_by_malware=False,
                        targeted_by_ransomware=False,
                        targeted_by_nation_state=False,
                        cvss_v3_vector=''
                    ),
                    technical_detail=technical_detail,
                    risk_rating=NUCLEI_RISK_MAPPING[severity])

        print(result)


if __name__ == '__main__':
    logger.info('starting agent ...')
    ZapAgent.main()
