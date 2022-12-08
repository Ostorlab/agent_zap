"""Module to parse zap json results."""
import dataclasses
from typing import Dict

from markdownify import markdownify as md
from ostorlab.agent.kb import kb
from ostorlab.agent.mixins import agent_report_vulnerability_mixin as vuln_mixin
from ostorlab.assets import domain_name

RISK_RATING_MAPPING = {
    0: vuln_mixin.RiskRating.INFO,
    1: vuln_mixin.RiskRating.LOW,
    2: vuln_mixin.RiskRating.MEDIUM,
    3: vuln_mixin.RiskRating.HIGH,
}

CONFIDENCE_MAPPING = {
    0: "FALSE_POSITIVE",
    1: "LOW",
    2: "MEDIUM",
    3: "HIGH",
    4: "CONFIRMED",
}


def _map_risk_rating(risk: int, confidence: int) -> vuln_mixin.RiskRating:
    """Map Zap risk and confidence to Ostorlab's risk."""
    if CONFIDENCE_MAPPING[confidence] in ("CONFIRMED", "HIGH"):
        return RISK_RATING_MAPPING[risk]
    else:
        return vuln_mixin.RiskRating.POTENTIALLY


def _build_technical_detail(
    target: str,
    header: str,
    method: str,
    uri: str,
    param: str,
    attack: str,
    evidence: str,
) -> str:
    """Build the technical detail markdown content."""
    return f"""{header}

* Target: {target}

```http
{method} {uri}
{param}
{attack}
{evidence}
```
    """


@dataclasses.dataclass
class Vulnerability:
    """Vulnerability dataclass to pass to the emit method."""

    entry: kb.Entry
    technical_detail: str
    risk_rating: vuln_mixin.RiskRating
    vulnerability_location: vuln_mixin.VulnerabilityLocation


def parse_results(results: Dict):
    """Parses JSON generated Zap results and yield vulnerability entries.

    Args:
        results: Parsed JSON output.

    Yields:
        Vulnerability entry.
    """
    for site in results.get("site", []):
        target = site.get("@name")
        host = site.get("@host")
        port = site.get("@port")
        for alert in site.get("alerts"):
            title = alert.get("name")
            description = md(alert.get("desc"))
            recommendation = md(alert.get("solution"))
            technical_detail_header = md(alert.get("otherinfo"))
            risk_rating_id = int(alert.get("riskcode"))
            confidence_id = int(alert.get("confidence"))
            references = {
                r: r
                for r in alert.get("reference").replace("<p>", "").split("</p>")
                if r != ""
            }
            cweid = alert.get("cweid")
            references[
                f"cwe-{cweid}"
            ] = f"https://nvd.nist.gov/vuln/detail/{cweid}.html"
            for instance in alert.get("instances"):
                uri = instance.get("uri")
                method = instance.get("method")
                param = instance.get("param")
                attack = instance.get("attack")
                evidence = instance.get("evidence")

                technical_detail = _build_technical_detail(
                    target=target,
                    header=technical_detail_header,
                    uri=uri,
                    method=method,
                    param=param,
                    attack=attack,
                    evidence=evidence,
                )
                vuln_location = vuln_mixin.VulnerabilityLocation(
                    asset=domain_name.DomainName(name=host),
                    metadata=[
                        vuln_mixin.VulnerabilityLocationMetadata(
                            metadata_type=vuln_mixin.MetadataType.URL, value=uri
                        ),
                        vuln_mixin.VulnerabilityLocationMetadata(
                            metadata_type=vuln_mixin.MetadataType.PORT, value=port
                        ),
                    ],
                )
                yield Vulnerability(
                    entry=kb.Entry(
                        title=title,
                        risk_rating=_map_risk_rating(
                            risk_rating_id, confidence_id
                        ).value,
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
                        cvss_v3_vector="",
                    ),
                    technical_detail=technical_detail,
                    risk_rating=_map_risk_rating(risk_rating_id, confidence_id),
                    vulnerability_location=vuln_location,
                )
