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


def testIsWebpackDevtoolWarningComment_whenWebpackDevtoolWarning_shouldReturnTrue() -> (
    None
):
    """Test detection of webpack's non-production devtool warning in the rule's other info."""
    otherinfo = (
        "The following pattern was used: \\bSELECT\\b and was detected in likely comment: "
        '"/*\n\n* ATTENTION: An "eval-source-map" devtool has been used.\n\n* This devtool is '
        'neither made for production nor for readable out", see evidence field for the '
        "suspicious comment/snippet."
    )
    assert result_parser.is_webpack_devtool_warning_comment(otherinfo) is True


def testIsWebpackDevtoolWarningComment_whenGenuineSqlComment_shouldReturnFalse() -> (
    None
):
    """Test that a genuine SQL comment is not treated as a webpack devtool warning."""
    otherinfo = (
        "The following pattern was used: \\bSELECT\\b and was detected in likely comment: "
        '"// SELECT * FROM users WHERE password IS NOT NULL", see evidence field for the '
        "suspicious comment/snippet."
    )
    assert result_parser.is_webpack_devtool_warning_comment(otherinfo) is False
    assert result_parser.is_webpack_devtool_warning_comment(None) is False
    assert result_parser.is_webpack_devtool_warning_comment("") is False


def testParseResults_whenSuspiciousCommentIsWebpackDevtoolWarning_shouldSuppressIt() -> (
    None
):
    """Test that a webpack devtool warning comment is suppressed while a genuine SQL one is reported."""
    with (
        pathlib.Path(__file__).parent / "zap-suspicious-comments-webpack-output.json"
    ).open("r", encoding="utf-8") as o:
        results = json.load(o)
        vulnz = list(result_parser.parse_results(results))
        assert len(vulnz) == 1
        assert vulnz[0].entry.title == "Information Disclosure - Suspicious Comments"
        assert "SELECT * FROM users" in vulnz[0].technical_detail
