"""Unit tests for result parser."""

import json
import pathlib

from ostorlab.agent.mixins import agent_report_vulnerability_mixin as vuln_mixin

from agent import result_parser


def testParseResults_always_yieldsValidVulnerabilities():
    """Test proper parsing of Zap JSON output."""
    with (pathlib.Path(__file__).parent / "zap-test-output.json").open(
        "r", encoding="utf-8"
    ) as o:
        results = json.load(o)
        vulnz = list(result_parser.parse_results(results))
        assert len(vulnz) == 216
        parsed_vulnz = [
            v for v in vulnz if v.entry.title == "Absence of Anti-CSRF Tokens"
        ]
        assert len(parsed_vulnz) == 11
        assert parsed_vulnz[0].risk_rating.name == "POTENTIALLY"
        assert (
            "http://projects.webappsec.org/Cross-Site-Request-Forgery"
            in parsed_vulnz[0].entry.references
        )
        assert "Phase: Architecture and Design" in parsed_vulnz[0].entry.recommendation
        assert (
            'action="/search" method="GET" role="search">'
            in parsed_vulnz[0].technical_detail
        )
        assert parsed_vulnz[0].risk_rating == vuln_mixin.RiskRating.POTENTIALLY


def testParseResults_whenMissingHeader_yieldsValidVulnerabilities(
    zap_missing_headers_output: json,
) -> None:
    """Test proper parsing of Zap JSON output, case when missing header vulnerability."""
    vulnz = list(result_parser.parse_results(zap_missing_headers_output))

    assert len(vulnz) == 23
    assert (
        vulnz[0].technical_detail
        == "Strict-Transport-Security Header Not Set at https://www.google.com/default"
    )
