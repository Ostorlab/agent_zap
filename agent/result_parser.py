"""Module to parse zap json results."""

import dataclasses
import json
import re
from typing import Any

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


RELATIVE_PATH_CONFUSION_TITLE = "Relative Path Confusion"

NON_STORABLE_CONTENT_TITLE = "Non-Storable Content"

COOKIE_SLACK_DETECTOR_TITLE = "Cookie Slack Detector"

SERVER_VERSION_INFO_LEAK_TITLE = (
    'Server Leaks Version Information via "Server" HTTP Response Header Field'
)

# ZAP's "Relative Path Confusion" rule (active scanner 10051) appends a random path
# to the scanned URL and raises an alert when the response contains relative resource
# references while the content type cannot rule out cross-content parsing. When the
# appended path returns the site's HTML shell as "text/html", the server explicitly
# serves an HTML document: there is no CSS/JS cross-content confusion, so those alerts
# are false positives.
_CONTENT_TYPE_LINE_PATTERN = re.compile(r'A Content Type of "([^"]*)" was specified')


def is_html_document_response(otherinfo: str | None) -> bool:
    """Whether the rule's extra info names ``text/html`` as the response content type.

    Args:
        otherinfo: The raw ``otherinfo`` of the alert, as produced by the ZAP rule.

    Returns:
        True when the response served at the appended path was an HTML document
        (``text/html``), False otherwise.
    """
    if otherinfo is None:
        return False
    match = _CONTENT_TYPE_LINE_PATTERN.search(otherinfo)
    return match is not None and match.group(1).lower().startswith("text/html")


# ZAP's "Non-Storable Content" rule (passive scanner 10049, alert ref 10049-1) raises
# when a response is not storable by a cache. When a response carries no cache directives
# (Expires, max-age, s-maxage, public) and its status code is not cacheable by default,
# the rule uses the status code itself as the instance evidence. HTTP 429 (Too Many
# Requests) is a rate-limit error response: it is transient and holds no content worth
# caching, so flagging it as non-storable is a false positive.
_RATE_LIMIT_STATUS_CODE = "429"


def is_rate_limit_response(evidence: str | None) -> bool:
    """Whether the alert's evidence is an HTTP 429 (rate-limit) status code.

    Args:
        evidence: The raw ``evidence`` of the alert instance, as produced by the ZAP rule.

    Returns:
        True when the evidence is the HTTP 429 status code, False otherwise.
    """
    return evidence == _RATE_LIMIT_STATUS_CODE


# ZAP's "Cookie Slack Detector" rule (active scanner 90027) drops one cookie per request
# and compares the response length against a baseline. When re-adding all cookies still
# does not restore the baseline, the rule reports that dropping the cookie "invalidated
# the session" (message ascanbeta.cookieslack.session.destroyed). Hotjar's analytics
# cookies (all "_hj"-prefixed, e.g. "_hjSessionUser_<siteId>") are third-party tracking
# identifiers, not application session cookies: a response-length change on a static asset
# is noise, so those alerts are false positives.
_HOTJAR_ANALYTICS_COOKIE_PREFIX = "_hj"
_SESSION_DESTROYED_COOKIE_PATTERN = re.compile(r"invalidated the session: \[([^\]]+)\]")


def is_third_party_analytics_cookie(otherinfo: str | None) -> bool:
    """Whether the alert's extra info names a Hotjar analytics cookie as the dropped session cookie.

    Args:
        otherinfo: The raw ``otherinfo`` of the alert, as produced by the ZAP rule.

    Returns:
        True when the rule reported that a Hotjar analytics cookie (``_hj*``) invalidated
        the session, False otherwise.
    """
    if otherinfo is None:
        return False
    match = _SESSION_DESTROYED_COOKIE_PATTERN.search(otherinfo)
    if match is None:
        return False
    return match.group(1).strip().lower().startswith(_HOTJAR_ANALYTICS_COOKIE_PREFIX)


# ZAP's "Server Header Version Information Leak" rule (passive scanner 10036, alert ref
# 10036-2) matches any digit in the Server response header and reports a version leak.
# Product names that embed a digit -- e.g. Amazon S3's "AmazonS3" banner -- are
# versionless, so those alerts are false positives. A genuine version leak carries a numeric
# version token separated from the product name: "Apache/2.4.1 (Unix)", "nginx/1.18.0",
# "Microsoft-IIS/10.0", "OFE/0.1" or "Oracle-Application-Server-11g".
_VERSION_TOKEN_PATTERN = re.compile(
    r"(?:^|[/\-_\s])(\d+(?:\.\d+)*[a-z]?)(?=$|[/\-_\s])"
)


def is_versionless_server_banner(evidence: str | None) -> bool:
    """Whether the alert's evidence is a Server banner with digits but no version token.

    Args:
        evidence: The raw ``evidence`` of the alert instance, i.e. the Server header value.

    Returns:
        True when the banner embeds a digit that is not part of a separated numeric version
        token (e.g. "AmazonS3"), False otherwise.
    """
    if not evidence:
        return False
    return _VERSION_TOKEN_PATTERN.search(evidence) is None


def _build_technical_detail(
    title: str,
    target: str,
    header: str,
    method: str,
    uri: str,
    param: str,
    attack: str,
    evidence: str,
) -> str:
    """Build the technical detail markdown content."""
    if "header not set" in title.lower():
        technical_detail = f"{title} at {uri}"
    else:
        technical_detail = f"""{header}

* Target: {target}

```http
{method} {uri}
{param}
{attack}
{evidence}
```
    """

    return technical_detail


def _compute_dna(
    vulnerability_title: str,
    vuln_location: vuln_mixin.VulnerabilityLocation | None,
    param: str,
) -> str | None:
    """Compute a deterministic, debuggable DNA representation for a vulnerability.

    Args:
        vulnerability_title: The title of the vulnerability.
        vuln_location: The location of the vulnerability.
        param: params of vulnerability

    Returns:
        A deterministic JSON representation of the vulnerability DNA.
    """
    if vuln_location is None:
        return None

    dna_data: dict[str, Any] = {"title": vulnerability_title, "param": param}

    location_dict: dict[str, Any] = vuln_location.to_dict()
    dna_data["location"] = location_dict

    return json.dumps(dna_data, sort_keys=True)


@dataclasses.dataclass
class Vulnerability:
    """Vulnerability dataclass to pass to the emit method."""

    entry: kb.Entry
    technical_detail: str
    risk_rating: vuln_mixin.RiskRating
    vulnerability_location: vuln_mixin.VulnerabilityLocation
    dna: str


def parse_results(results: dict[str, Any], scope_urls_regex: str | None = None):
    """Parses JSON generated Zap results and yield vulnerability entries.

    Args:
        results: Parsed JSON output.

    Yields:
        Vulnerability entry.
    """
    for site in results.get("site", []):
        target = site.get("@name")
        if scope_urls_regex is not None and re.match(scope_urls_regex, target) is None:
            continue

        host = site.get("@host")
        for alert in site.get("alerts"):
            title = alert.get("name")
            if title == COOKIE_SLACK_DETECTOR_TITLE and is_third_party_analytics_cookie(
                otherinfo=alert.get("otherinfo")
            ):
                continue

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
            references[f"cwe-{cweid}"] = (
                f"https://nvd.nist.gov/vuln/detail/{cweid}.html"
            )
            for instance in alert.get("instances"):
                uri = instance.get("uri")
                method = instance.get("method")
                param = instance.get("param")
                attack = instance.get("attack")
                evidence = instance.get("evidence")

                if title == RELATIVE_PATH_CONFUSION_TITLE and is_html_document_response(
                    otherinfo=alert.get("otherinfo")
                ):
                    continue

                if title == NON_STORABLE_CONTENT_TITLE and is_rate_limit_response(
                    evidence=evidence
                ):
                    continue

                if (
                    title == SERVER_VERSION_INFO_LEAK_TITLE
                    and is_versionless_server_banner(evidence=evidence)
                ):
                    continue

                technical_detail = _build_technical_detail(
                    title=title,
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
                        )
                    ],
                )
                dna = _compute_dna(
                    vulnerability_title=title,
                    vuln_location=vuln_location,
                    param=param,
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
                    dna=dna,
                )
