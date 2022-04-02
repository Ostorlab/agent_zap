import json
import pathlib

from ostorlab.agent.kb import kb
from ostorlab.agent.mixins import agent_report_vulnerability_mixin as vuln_mixin

from agent import result_parser


def testParseResults_always_yieldsValidVulnerabilities():
    """Test proper parsing of Zap JSON output."""
    with (pathlib.Path(__file__).parent / 'zap-test-output.json').open('r', encoding='utf-8') as o:
        results = json.load(o)

        vulnz = list(result_parser.parse_results(results))

        assert result_parser.Vulnerability(
            entry=kb.Entry(title='Absence of Anti-CSRF Tokens',
                           risk_rating=4,
                           references={
                               'http://projects.webappsec.org/Cross-Site-Request-Forgery':
                                   'http://projects.webappsec.org/Cross-Site-Request-Forgery',
                               'http://cwe.mitre.org/data/definitions/352.html':
                                   'http://cwe.mitre.org/data/definitions/352.html',
                               'cwe-352': 'https://nvd.nist.gov/vuln/detail/352.html'},
                           short_description="No Anti-CSRF tokens were found in a HTML submission form.\n"
                                             "\nA cross-site request forgery is an attack that involves forcing a"
                                             " victim to send an HTTP request to a target destination without their"
                                             " knowledge or intent in order to perform an action as the victim. The"
                                             " underlying cause is application functionality using predictable URL/form"
                                             " actions in a repeatable way. The nature of the attack is that CSRF"
                                             " exploits the trust that a web site has for a user. By contrast,"
                                             " cross-site scripting (XSS) exploits the trust that a user has for"
                                             " a web site. Like XSS, CSRF attacks are not necessarily cross-site,"
                                             " but they can be. Cross-site request forgery is also known as CSRF"
                                             ", XSRF, one-click attack, session riding, confused deputy, and sea"
                                             " surf.\n\nCSRF attacks are effective in a number of situations,"
                                             " including:\n\n * The victim has an active session on the target site."
                                             "\n\n * The victim is authenticated via HTTP auth on the target site."
                                             "\n\n * The victim is on the same local network as the target site.\n\n"
                                             "CSRF has primarily been used to perform an action against a target site"
                                             " using the victim's privileges, but recent techniques have been"
                                             " discovered to disclose information by gaining access to the response."
                                             " The risk of information disclosure is dramatically increased when the"
                                             " target site is vulnerable to XSS, because XSS can be used as a platform"
                                             " for CSRF, allowing the attack to operate within the bounds of the"
                                             " same-origin policy.\n\n",
                           description="No Anti-CSRF tokens were found in a HTML submission form.\n\nA cross-site"
                                       " request forgery is an attack that involves forcing a victim to send an"
                                       " HTTP request to a target destination without their knowledge or intent in"
                                       " order to perform an action as the victim. The underlying cause is application"
                                       " functionality using predictable URL/form actions in a repeatable way. The"
                                       " nature of the attack is that CSRF exploits the trust that a web site has for"
                                       " a user. By contrast, cross-site scripting (XSS) exploits the trust that a"
                                       " user has for a web site. Like XSS, CSRF attacks are not necessarily"
                                       " cross-site, but they can be. Cross-site request forgery is also known as"
                                       " CSRF, XSRF, one-click attack, session riding, confused deputy, and sea"
                                       " surf.\n\nCSRF attacks are effective in a number of situations, including:"
                                       "\n\n * The victim has an active session on the target site.\n\n * The victim"
                                       " is authenticated via HTTP auth on the target site.\n\n * The victim is on the"
                                       " same local network as the target site.\n\nCSRF has primarily been used to"
                                       " perform an action against a target site using the victim's privileges, but"
                                       " recent techniques have been discovered to disclose information by gaining"
                                       " access to the response. The risk of information disclosure is dramatically"
                                       " increased when the target site is vulnerable to XSS, because XSS can be used"
                                       " as a platform for CSRF, allowing the attack to operate within the bounds of"
                                       " the same-origin policy.\n\n",
                           recommendation='Phase: Architecture and Design\n\nUse a vetted library or framework that'
                                          ' does not allow this weakness to occur or provides constructs that make this'
                                          ' weakness easier to avoid.\n\nFor example, use anti-CSRF packages such as'
                                          ' the OWASP CSRFGuard.\n\nPhase: Implementation\n\nEnsure that your'
                                          ' application is free of cross-site scripting issues, because most CSRF'
                                          ' defenses can be bypassed using attacker-controlled script.\n\nPhase:'
                                          ' Architecture and Design\n\nGenerate a unique nonce for each form, place'
                                          ' the nonce into the form, and verify the nonce upon receipt of the form. Be'
                                          ' sure that the nonce is not predictable (CWE-330).\n\nNote that this can be'
                                          ' bypassed using XSS.\n\nIdentify especially dangerous operations. When the'
                                          ' user performs a dangerous operation, send a separate confirmation request'
                                          ' to ensure that the user intended to perform that operation.\n\nNote that'
                                          ' this can be bypassed using XSS.\n\nUse the ESAPI Session Management'
                                          ' control.\n\nThis control includes a component for CSRF.\n\nDo not use the'
                                          ' GET method for any request that triggers a state change.\n\nPhase:'
                                          ' Implementation\n\nCheck the HTTP Referer header to see if the request'
                                          ' originated from an expected page. This could break legitimate'
                                          ' functionality, because users or proxies may have disabled sending the'
                                          ' Referer for privacy reasons.\n\n',
                           security_issue=True, privacy_issue=False,
                           has_public_exploit=False, targeted_by_malware=False,
                           targeted_by_ransomware=False, targeted_by_nation_state=False,
                           cvss_v3_vector=''),
            technical_detail='No known Anti-CSRF token [anticsrf, CSRFToken, \\_\\_RequestVerificationToken,'
                             ' csrfmiddlewaretoken, authenticity\\_token, OWASP\\_CSRFTOKEN, anoncsrf, csrf\\_token,'
                             ' \\_csrf, \\_csrfSecret, \\_\\_csrf\\_magic, CSRF, \\_token, \\_csrf\\_token] was found'
                             ' in the following HTML form: [Form 1: "btnI" "btnK" "ei" "iflsig" "q" "source" ].\n\n\n'
                             '\n* Target: https://www.google.com\n\n```http\nGET https://www.google.com\n\n\n<form'
                             ' action="/search" method="GET" role="search">\n```\n    ',
            risk_rating=vuln_mixin.RiskRating.POTENTIALLY) in vulnz
