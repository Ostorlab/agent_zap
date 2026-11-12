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


def testIsHtmlDocumentResponse_whenTextHtmlContentType_shouldReturnTrue() -> None:
    """Test detection of an explicitly served HTML document in the rule's other info."""
    otherinfo = (
        "No <base> tag was specified in the HTML <head> tag to define the location "
        'for relative URLs.\n\nA Content Type of "text/html" was specified. If the '
        "web browser is employing strict parsing rules, this will prevent cross-content "
        "attacks from succeeding."
    )
    assert result_parser.is_html_document_response(otherinfo) is True


def testIsHtmlDocumentResponse_whenNoContentType_shouldReturnFalse() -> None:
    """Test that a missing content type is not treated as an HTML document response."""
    otherinfo = (
        "No <base> tag was specified in the HTML <head> tag to define the location "
        "for relative URLs.\n\nNo Content Type was specified, so Quirks Mode is not "
        "required to exploit the vulnerability in the web browser."
    )
    assert result_parser.is_html_document_response(otherinfo) is False
    assert result_parser.is_html_document_response(None) is False
    assert result_parser.is_html_document_response("") is False


def testParseResults_whenRelativePathConfusionServesHtml_shouldSuppressHtmlDocuments() -> (
    None
):
    """Test that a text/html Relative Path Confusion alert is suppressed while a cross-content one is reported."""
    with (
        pathlib.Path(__file__).parent / "zap-relative-path-confusion-html-output.json"
    ).open("r", encoding="utf-8") as o:
        results = json.load(o)
        vulnz = list(result_parser.parse_results(results))
        assert len(vulnz) == 1
        assert vulnz[0].entry.title == "Relative Path Confusion"
        assert "No Content Type was specified" in vulnz[0].technical_detail


def testIsRateLimitResponse_when429Evidence_shouldReturnTrue() -> None:
    """Test detection of an HTTP 429 (rate-limit) status code in the alert evidence."""
    assert result_parser.is_rate_limit_response("429") is True


def testIsRateLimitResponse_whenOtherEvidence_shouldReturnFalse() -> None:
    """Test that non-rate-limit evidence is not treated as a rate-limit response."""
    assert result_parser.is_rate_limit_response("no-store") is False
    assert result_parser.is_rate_limit_response("private") is False
    assert result_parser.is_rate_limit_response("Authorization:") is False
    assert result_parser.is_rate_limit_response("500") is False
    assert result_parser.is_rate_limit_response(None) is False
    assert result_parser.is_rate_limit_response("") is False


def testParseResults_whenNonStorableRateLimit_shouldSuppressRateLimitResponses() -> (
    None
):
    """Test that a rate-limit Non-Storable Content alert is suppressed while a genuine one is reported."""
    with (
        pathlib.Path(__file__).parent / "zap-non-storable-rate-limit-output.json"
    ).open("r", encoding="utf-8") as o:
        results = json.load(o)
        vulnz = list(result_parser.parse_results(results))
        assert len(vulnz) == 1
        assert vulnz[0].entry.title == "Non-Storable Content"
        assert "no-store" in vulnz[0].technical_detail
