"""Unit tests for result parser."""

import json
import pathlib
import time

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


def testIsImmutableStaticAsset_whenContentHashedAssetWithYearCache_shouldReturnTrue() -> (
    None
):
    """Test detection of a content-hashed immutable static asset served with a one-year cache."""
    assert (
        result_parser.is_immutable_static_asset(
            "https://pigment.app/assets/CypressDebug-D5vcAvqv.js",
            "max-age=31536000",
        )
        is True
    )
    assert (
        result_parser.is_immutable_static_asset(
            "https://example.com/js/main.a1b2c3d4e5f6.js", "public, max-age=31536000"
        )
        is True
    )
    assert (
        result_parser.is_immutable_static_asset(
            "https://example.com/css/app-9f8e7d6c.css", "max-age=31536000"
        )
        is True
    )


def testIsImmutableStaticAsset_whenNotImmutableAsset_shouldReturnFalse() -> None:
    """Test that dynamic or non-content-hashed responses are not treated as immutable static assets."""
    # Dynamic, user-specific page cached for a year: the genuine concern, must keep reporting.
    assert (
        result_parser.is_immutable_static_asset(
            "https://pigment.app/account", "max-age=31536000"
        )
        is False
    )
    # Content-hashed asset but a short-lived cache.
    assert (
        result_parser.is_immutable_static_asset(
            "https://example.com/js/main.a1b2c3d4.js", "max-age=3600"
        )
        is False
    )
    # Cache directives without a max-age.
    assert (
        result_parser.is_immutable_static_asset(
            "https://example.com/js/main.a1b2c3d4.js", "public"
        )
        is False
    )
    # Non-content-hashed filename with a long-lived cache.
    assert (
        result_parser.is_immutable_static_asset(
            "https://example.com/js/app.js", "max-age=31536000"
        )
        is False
    )
    assert result_parser.is_immutable_static_asset(None, "max-age=31536000") is False
    assert (
        result_parser.is_immutable_static_asset("https://example.com/app.js", None)
        is False
    )
    assert result_parser.is_immutable_static_asset("", "") is False


def testParseResults_whenStorableCacheableImmutableAsset_shouldSuppressImmutableAsset() -> (
    None
):
    """Test that an immutable static asset Storable and Cacheable alert is suppressed while a dynamic one is reported."""
    with (
        pathlib.Path(__file__).parent
        / "zap-storable-cacheable-immutable-asset-output.json"
    ).open("r", encoding="utf-8") as o:
        results = json.load(o)
        vulnz = list(result_parser.parse_results(results))
        assert len(vulnz) == 1
        assert vulnz[0].entry.title == "Storable and Cacheable Content"
        assert "CypressDebug-D5vcAvqv.js" not in vulnz[0].technical_detail
        assert "https://pigment.app/account" in vulnz[0].technical_detail


def testIsThirdPartyAnalyticsCookie_whenHotjarAnalyticsCookie_shouldReturnTrue() -> (
    None
):
    """Test detection of a Hotjar analytics cookie in the rule's session-destroyed extra info."""
    otherinfo = (
        "Dropping this cookie appears to have invalidated the session: "
        "[_hjSessionUser_2738795] A follow-on request with all original cookies still had "
        "a different response than the original request."
    )
    assert result_parser.is_third_party_analytics_cookie(otherinfo) is True
    assert (
        result_parser.is_third_party_analytics_cookie(
            "Dropping this cookie appears to have invalidated the session: "
            "[_hjSession_12345] A follow-on request with all original cookies still had "
            "a different response than the original request."
        )
        is True
    )


def testIsThirdPartyAnalyticsCookie_whenSessionCookie_shouldReturnFalse() -> None:
    """Test that an application session cookie is not treated as a Hotjar analytics cookie."""
    otherinfo = (
        "Dropping this cookie appears to have invalidated the session: [JSESSIONID] "
        "A follow-on request with all original cookies still had a different response "
        "than the original request."
    )
    assert result_parser.is_third_party_analytics_cookie(otherinfo) is False
    assert result_parser.is_third_party_analytics_cookie(None) is False
    assert result_parser.is_third_party_analytics_cookie("") is False
    assert result_parser.is_third_party_analytics_cookie("no cookie here") is False


def testIsUserAgentFuzzWithoutResponseDifference_whenNoDifferenceStored_shouldReturnTrue() -> (
    None
):
    """Test detection of a User Agent Fuzzer alert that records no response difference."""
    assert result_parser.is_user_agent_fuzz_without_response_difference("", "") is True
    assert (
        result_parser.is_user_agent_fuzz_without_response_difference(None, None) is True
    )
    assert (
        result_parser.is_user_agent_fuzz_without_response_difference("", None) is True
    )


def testIsUserAgentFuzzWithoutResponseDifference_whenDifferenceStored_shouldReturnFalse() -> (
    None
):
    """Test that a User Agent Fuzzer alert that demonstrates a response difference is not suppressed."""
    otherinfo = "A response difference was observed for the fuzzed User-Agent."
    evidence = (
        "The response status code changed from 200 to 429 and the response body "
        "hash differed from the original response."
    )
    assert (
        result_parser.is_user_agent_fuzz_without_response_difference(
            otherinfo, evidence
        )
        is False
    )
    assert (
        result_parser.is_user_agent_fuzz_without_response_difference(otherinfo, "")
        is False
    )
    assert (
        result_parser.is_user_agent_fuzz_without_response_difference("", evidence)
        is False
    )


def testParseResults_whenUserAgentFuzzerWithoutResponseDifference_shouldSuppress() -> (
    None
):
    """Test that a User Agent Fuzzer alert storing no response difference is suppressed while one demonstrating a difference is reported."""
    with (pathlib.Path(__file__).parent / "zap-user-agent-fuzzer-output.json").open(
        "r", encoding="utf-8"
    ) as o:
        results = json.load(o)
        vulnz = list(result_parser.parse_results(results))
        assert len(vulnz) == 1
        assert vulnz[0].entry.title == "User Agent Fuzzer"
        assert "Googlebot" in vulnz[0].technical_detail
        assert (
            "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)"
            not in vulnz[0].technical_detail
        )


def testParseResults_whenCookieSlackFlagsHotjarCookie_shouldSuppressAnalyticsCookie() -> (
    None
):
    """Test that a Hotjar analytics cookie Cookie Slack Detector alert is suppressed while a genuine one is reported."""
    with (pathlib.Path(__file__).parent / "zap-cookie-slack-hotjar-output.json").open(
        "r", encoding="utf-8"
    ) as o:
        results = json.load(o)
        vulnz = list(result_parser.parse_results(results))
        assert len(vulnz) == 1
        assert vulnz[0].entry.title == "Cookie Slack Detector"
        assert "JSESSIONID" in vulnz[0].technical_detail


def testIsFutureTimestamp_whenFutureEpoch_shouldReturnTrue() -> None:
    """Test detection of an evidence value that parses to a future Unix timestamp."""
    future = int(time.time()) + 10_000_000
    assert result_parser.is_future_timestamp(str(future)) is True


def testIsFutureTimestamp_whenPastOrInvalid_shouldReturnFalse() -> None:
    """Test that past and non-numeric evidence is not treated as a future timestamp."""
    past = int(time.time()) - 10_000_000
    assert result_parser.is_future_timestamp(str(past)) is False
    assert result_parser.is_future_timestamp("1704114087") is False
    assert result_parser.is_future_timestamp(None) is False
    assert result_parser.is_future_timestamp("") is False
    assert result_parser.is_future_timestamp("not-a-timestamp") is False
    assert result_parser.is_future_timestamp("123") is False


def testParseResults_whenTimestampDisclosureResolvesToFuture_shouldSuppressFutureTimestamps() -> (
    None
):
    """Test that a future-dated Timestamp Disclosure - Unix alert is suppressed while a past-dated one is reported."""
    with (
        pathlib.Path(__file__).parent / "zap-timestamp-disclosure-future-output.json"
    ).open("r", encoding="utf-8") as o:
        results = json.load(o)

    future_instance = results["site"][0]["alerts"][0]["instances"][0]
    future_instance["evidence"] = str(int(time.time()) + 10_000_000)
    vulnz = list(result_parser.parse_results(results))
    assert len(vulnz) == 1
    assert vulnz[0].entry.title == "Timestamp Disclosure - Unix"
    assert "1704114087" in vulnz[0].technical_detail


def testIsOriginBannerReportedAsProxy_whenSameBanner_shouldReturnTrue() -> None:
    """Test detection of the origin's own banner being listed as an intermediate proxy."""
    otherinfo = (
        "Using the TRACE, OPTIONS, and TRACK methods, the following proxy servers have been "
        "identified between ZAP and the application/web server:\n"
        "- AMEX\n"
        "\n"
        "The following web/application server has been identified:\n"
        "- AMEX\n"
    )
    assert result_parser.is_origin_banner_reported_as_proxy(otherinfo) is True


def testIsOriginBannerReportedAsProxy_whenDistinctProxy_shouldReturnFalse() -> None:
    """Test that a genuine intermediate proxy with a distinct banner is not suppressed."""
    otherinfo = (
        "Using the TRACE, OPTIONS, and TRACK methods, the following proxy servers have been "
        "identified between ZAP and the application/web server:\n"
        "- nginx/1.22\n"
        "\n"
        "The following web/application server has been identified:\n"
        "- Apache/2.4.58\n"
    )
    assert result_parser.is_origin_banner_reported_as_proxy(otherinfo) is False
    assert result_parser.is_origin_banner_reported_as_proxy(None) is False
    assert result_parser.is_origin_banner_reported_as_proxy("") is False


def testIsOriginBannerReportedAsProxy_whenPartialMatch_shouldReturnFalse() -> None:
    """Test that a real proxy mixed with the origin banner is still reported."""
    otherinfo = (
        "Using the TRACE, OPTIONS, and TRACK methods, the following proxy servers have been "
        "identified between ZAP and the application/web server:\n"
        "- AMEX\n"
        "- nginx/1.22\n"
        "\n"
        "The following web/application server has been identified:\n"
        "- AMEX\n"
    )
    assert result_parser.is_origin_banner_reported_as_proxy(otherinfo) is False


def testIsOriginBannerReportedAsProxy_whenSilentProxy_shouldReturnFalse() -> None:
    """Test that a 'silent' proxy keeps the alert reported even when the banner matches."""
    otherinfo = (
        "Using the TRACE, OPTIONS, and TRACK methods, the following proxy servers have been "
        "identified between ZAP and the application/web server:\n"
        "- AMEX\n"
        "\n"
        "The following web/application server has been identified:\n"
        "- AMEX\n"
        "\n"
        "The following 'silent' proxy servers were identified. Due to their behaviour, it is "
        "not known at which point in the network topology these proxy servers reside:\n"
        "- Citrix NetScaler\n"
    )
    assert result_parser.is_origin_banner_reported_as_proxy(otherinfo) is False


def testParseResults_whenProxyDisclosureShowsOriginBanner_shouldSuppressOriginBanner() -> (
    None
):
    """Test that an origin-banner Proxy Disclosure alert is suppressed while a genuine one is reported."""
    with (
        pathlib.Path(__file__).parent / "zap-proxy-disclosure-origin-banner-output.json"
    ).open("r", encoding="utf-8") as o:
        results = json.load(o)
        vulnz = list(result_parser.parse_results(results))
        assert len(vulnz) == 1
        assert vulnz[0].entry.title == "Proxy Disclosure"
        assert "Apache/2.4.58" in vulnz[0].technical_detail


def testIsVersionlessServerBanner_whenAmazonS3Banner_shouldReturnTrue() -> None:
    """Test that a Server banner with an embedded digit but no version token is detected."""
    assert result_parser.is_versionless_server_banner("AmazonS3") is True


def testIsVersionlessServerBanner_whenVersionedBanner_shouldReturnFalse() -> None:
    """Test that banners carrying a separated numeric version token are not versionless."""
    assert result_parser.is_versionless_server_banner("Apache/2.4.1 (Unix)") is False
    assert result_parser.is_versionless_server_banner("nginx/1.18.0") is False
    assert result_parser.is_versionless_server_banner("Microsoft-IIS/10.0") is False
    assert result_parser.is_versionless_server_banner("OFE/0.1") is False
    assert (
        result_parser.is_versionless_server_banner("Jetty(9.4.39.v20210325)") is False
    )
    assert result_parser.is_versionless_server_banner("Jetty(11.0.15)") is False
    assert result_parser.is_versionless_server_banner("Apache/2.4.x") is False
    assert (
        result_parser.is_versionless_server_banner("Oracle-Application-Server-11g")
        is False
    )
    assert result_parser.is_versionless_server_banner(None) is False
    assert result_parser.is_versionless_server_banner("") is False


def testParseResults_whenServerBannerVersionless_shouldSuppressVersionLeak() -> None:
    """Test that a versionless Server banner alert is suppressed while a genuine version leak is reported."""
    with (pathlib.Path(__file__).parent / "zap-server-version-banner-output.json").open(
        "r", encoding="utf-8"
    ) as o:
        results = json.load(o)
        vulnz = list(result_parser.parse_results(results))
        assert len(vulnz) == 1
        assert (
            vulnz[0].entry.title
            == 'Server Leaks Version Information via "Server" HTTP Response Header Field'
        )
        assert "Apache/2.4.1" in vulnz[0].technical_detail
