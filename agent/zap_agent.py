"""Zap agent implementation"""
import io
import json
import logging
import pathlib
import subprocess
import tempfile
from typing import List

from ostorlab.agent import agent
from ostorlab.agent import message as m
from ostorlab.agent.kb import kb
from ostorlab.agent.mixins import agent_report_vulnerability_mixin as vuln_mixin
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
    0: vuln_mixin.RiskRating.INFO,
    1: vuln_mixin.RiskRating.LOW,
    2: vuln_mixin.RiskRating.MEDIUM,
    3: vuln_mixin.RiskRating.HIGH,
}

CONFIDENCE_MAPPING = {
    0: 'FALSE_POSITIVE',
    1: 'LOW',
    2: 'MEDIUM',
    3: 'HIGH',
    4: 'CONFIRMED',
}


def _map_risk_rating(risk: int, confidence: int) -> vuln_mixin.RiskRating:
    if CONFIDENCE_MAPPING[confidence] in ('CONFIRMED', 'HIGH'):
        return RISK_RATING_MAPPING[risk]
    else:
        return vuln_mixin.RiskRating.POTENTIALLY


def _build_technical_detail(target, header, method, uri, param, attack, evidence) -> str:
    return f'''{header}

* Target: {target}

```http
{method} {uri}
{param}
{attack}
{evidence}
```
    '''


class ZapAgent(agent.Agent, vuln_mixin.AgentReportVulnMixin):
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
        logger.info('results: %s', result)
        for site in result.get('site', []):
            target = site.get('@name')
            for alert in site.get('alerts'):
                title = alert.get('name')
                description = alert.get('desc')
                recommendation = alert.get('solution')
                technical_detail_header = alert.get('otherinfo')
                risk_rating_id = int(alert.get('riskcode'))
                confidence_id = int(alert.get('confidence'))
                references = {r: r for r in alert.get('reference').replace('<p>', '').split('</p>') if r is not ''}
                cweid = alert.get('cweid')
                references[f'cwe-{cweid}'] = f"""https://nvd.nist.gov/vuln/detail/{cweid}.html"""
                for instance in alert.get('instances'):
                    uri = instance.get('uri')
                    method = instance.get('method')
                    param = instance.get('param')
                    attack = instance.get('attack')
                    evidence = instance.get('evidence')

                    technical_detail = _build_technical_detail(
                        target,
                        technical_detail_header,
                        uri,
                        method,
                        param,
                        attack,
                        evidence)

                    self.report_vulnerability(
                        entry=kb.Entry(
                            title=title,
                            risk_rating=_map_risk_rating(risk_rating_id, confidence_id).value,
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
                        risk_rating=_map_risk_rating(risk_rating_id, confidence_id))


if __name__ == '__main__':
    logger.info('starting agent ...')
    ZapAgent.main()
