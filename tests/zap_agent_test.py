"""Unittests for Zap agent."""
import pathlib
import json


def testAgentZap_whenDomainNameAsset_RunScan(scan_message, test_agent, mocker, agent_mock):
    """Tests running the agent and emitting vulnerabilities."""
    with (pathlib.Path(__file__).parent / 'zap-test-output.json').open('r', encoding='utf-8') as o:
        mock_scan = mocker.patch('agent.zap_wrapper.ZapWrapper.scan', return_value=json.load(o))
        test_agent.start()
        test_agent.process(scan_message)
        assert mock_scan.is_called_once_with('https://test.ostorlab.co')
        assert len(agent_mock) > 0
        assert agent_mock[0].selector == 'v3.report.vulnerability'


def testAgentZap_whenLinkAsset_RunScan(scan_message_link, test_agent, mocker, agent_mock):
    """Tests running the agent and emitting vulnerabilities."""
    with (pathlib.Path(__file__).parent / 'zap-test-output.json').open('r', encoding='utf-8') as o:
        mock_scan = mocker.patch('agent.zap_wrapper.ZapWrapper.scan', return_value=json.load(o))
        test_agent.start()
        test_agent.process(scan_message_link)
        assert mock_scan.is_called_once_with('https://test.ostorlab.co')
        assert len(agent_mock) > 0
        assert agent_mock[0].selector == 'v3.report.vulnerability'
