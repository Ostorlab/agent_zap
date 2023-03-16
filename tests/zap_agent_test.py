"""Unittests for Zap agent."""
import pathlib
import json
import subprocess


def testAgentZap_whenDomainNameAsset_RunScan(
    scan_message, test_agent, mocker, agent_mock
):
    """Tests running the agent and emitting vulnerabilities."""
    with (pathlib.Path(__file__).parent / "zap-test-output.json").open(
        "r", encoding="utf-8"
    ) as o:
        mock_scan = mocker.patch(
            "agent.zap_wrapper.ZapWrapper.scan", return_value=json.load(o)
        )
        test_agent.start()
        test_agent.process(scan_message)
        assert mock_scan.is_called_once_with("https://test.ostorlab.co")
        assert len(agent_mock) > 0
        assert "v3.report.vulnerability" in [a.selector for a in agent_mock]
        assert ["domain_name", "metadata"] in [
            list(a.data.get("vulnerability_location", {}).keys()) for a in agent_mock
        ]


def testAgentZap_whenDomainNameAssetAndUrlScope_RunScan(
    scan_message_2, test_agent_with_url_scope, mocker, agent_mock
):
    """Tests running the agent and emitting vulnerabilities."""
    with (pathlib.Path(__file__).parent / "zap-test-output.json").open(
        "r", encoding="utf-8"
    ) as o:
        mock_scan = mocker.patch(
            "agent.zap_wrapper.ZapWrapper.scan", return_value=json.load(o)
        )
        test_agent_with_url_scope.start()
        test_agent_with_url_scope.process(scan_message_2)
        assert mock_scan.is_called_once_with("https://ostorlab.co")
        assert len(agent_mock) > 0
        assert "v3.report.vulnerability" in [a.selector for a in agent_mock]
        assert ["domain_name", "metadata"] in [
            list(a.data.get("vulnerability_location", {}).keys()) for a in agent_mock
        ]


def testAgentZap_whenDomainNameAssetAndUrlScope_NotRunScan(
    scan_message, test_agent_with_url_scope, mocker, agent_mock
):
    """Tests running the agent and emitting vulnerabilities."""
    with (pathlib.Path(__file__).parent / "zap-test-output.json").open(
        "r", encoding="utf-8"
    ) as o:
        mock_scan = mocker.patch(
            "agent.zap_wrapper.ZapWrapper.scan", return_value=json.load(o)
        )
        test_agent_with_url_scope.start()
        test_agent_with_url_scope.process(scan_message)
        mock_scan.assert_not_called()


def testAgentZap_whenLinkAsset_RunScan(
    scan_message_link, test_agent, mocker, agent_mock
):
    """Tests running the agent and emitting vulnerabilities."""
    with (pathlib.Path(__file__).parent / "zap-test-output.json").open(
        "r", encoding="utf-8"
    ) as o:
        mock_scan = mocker.patch(
            "agent.zap_wrapper.ZapWrapper.scan", return_value=json.load(o)
        )
        test_agent.start()
        test_agent.process(scan_message_link)
        assert mock_scan.is_called_once_with("https://test.ostorlab.co")
        assert len(agent_mock) > 0
        assert agent_mock[0].selector == "v3.report.vulnerability"


def testAgentZap_whenScanResultsFileIsEmpty_doesNotCrash(
    scan_message, test_agent, mocker, agent_mock
):
    """Tests running the agent when the scan results file is empty and does not cause a crash."""

    mocker.patch("subprocess.run", return_value=subprocess.CalledProcessError(cmd="", returncode=0))
    mocker.patch("agent.zap_wrapper.OUTPUT_DIR", '.')
    test_agent.start()
    test_agent.process(scan_message)

    assert len(agent_mock) == 0
