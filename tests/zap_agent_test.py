"""Unittests for Zap agent."""

import io
import json
import pathlib
import subprocess
from unittest import mock

from ostorlab.agent.message import message
from pytest_mock import plugin

from agent import zap_agent

VPN_CONFIG = """[Interface]
# NetShield = 1
# Moderate NAT = off
PrivateKey = PRIVATEKEY=
Address = 0.0.0.0/32
DNS = 1.1.1.1

[Peer]
# AE#12
PublicKey = PUBLICKEY=
AllowedIPs = 0.0.0.0/0
Endpoint = 2.2.2.2:22
"""

EXEC_COMMAND_OUTPUT = subprocess.CompletedProcess(
    args="",
    returncode=0,
    stderr=io.BytesIO(b"..."),
    stdout=io.BytesIO(b"App starting..."),
)


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
        mocker.patch("subprocess.run", return_value=EXEC_COMMAND_OUTPUT)
        mocker.patch("builtins.open", new_callable=mock.mock_open())
        test_agent.start()
        test_agent.process(scan_message)
        assert mock_scan.is_called_once_with("https://test.ostorlab.co")
        assert len(agent_mock) > 0
        assert "v3.report.vulnerability" in [a.selector for a in agent_mock]
        assert agent_mock[0].data.get("vulnerability_location") == {'domain_name': {'name': 'www.google.com'}, 'metadata': [{'type': 'URL', 'value': 'https://www.google.com/url?q=https://policies.google.com/privacy%3Fhl%3Dfr-MA%26fg%3D1&sa=U&usg=AOvVaw0g_jc-KYZ4RUoufhMKiYyz&ved=0ahUKEwivxPDLmuv2AhXE4IUKHZERCIQQ8awCCA0'}, {'type': 'PORT', 'value': '443'}]}
        assert ["domain_name", "metadata"] in [
            list(a.data.get("vulnerability_location", {}).keys()) for a in agent_mock
        ]
        assert agent_mock[0].data.get("dna") == '{"location": {"domain_name": {"name": "www.google.com"}, "metadata": [{"type": "PORT", "value": "443"}, {"type": "URL", "value": "https://www.google.com/url?q=https://policies.google.com/privacy%3Fhl%3Dfr-MA%26fg%3D1&sa=U&usg=AOvVaw0g_jc-KYZ4RUoufhMKiYyz&ved=0ahUKEwivxPDLmuv2AhXE4IUKHZERCIQQ8awCCA0"}]}, "param": "q", "title": "Open Redirect"}'
        assert all(
            agent_mock[i].data.get("dna") is not None for i in range(len(agent_mock))
        ) is True


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
        mocker.patch("subprocess.run", return_value=EXEC_COMMAND_OUTPUT)
        mocker.patch("builtins.open", new_callable=mock.mock_open())
        test_agent_with_url_scope.start()
        test_agent_with_url_scope.process(scan_message_2)
        assert mock_scan.is_called_once_with("https://ostorlab.co")
        assert len(agent_mock) > 0
        assert "v3.report.vulnerability" in [a.selector for a in agent_mock]
        assert ["domain_name", "metadata"] in [
            list(a.data.get("vulnerability_location", {}).keys()) for a in agent_mock
        ]
        assert all(
            agent_mock[i].data.get("dna") is not None for i in range(len(agent_mock))
        )


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
        mocker.patch("subprocess.run", return_value=EXEC_COMMAND_OUTPUT)
        mocker.patch("builtins.open", new_callable=mock.mock_open())
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
        mocker.patch("subprocess.run", return_value=EXEC_COMMAND_OUTPUT)
        mocker.patch("builtins.open", new_callable=mock.mock_open())
        test_agent.start()
        test_agent.process(scan_message_link)
        assert mock_scan.is_called_once_with("https://test.ostorlab.co")
        assert len(agent_mock) > 0
        assert agent_mock[0].selector == "v3.report.vulnerability"


def testAgentZap_whenScanResultsFileIsEmpty_doesNotCrash(
    scan_message, test_agent, mocker, agent_mock
):
    """Tests running the agent when the scan results file is empty and does not cause a crash."""

    mocker.patch(
        "subprocess.run",
        return_value=subprocess.CalledProcessError(cmd="", returncode=0),
    )
    mocker.patch("subprocess.run", return_value=EXEC_COMMAND_OUTPUT)
    mocker.patch("builtins.open", new_callable=mock.mock_open())
    mocker.patch("agent.zap_wrapper.OUTPUT_DIR", ".")
    test_agent.start()
    test_agent.process(scan_message)

    assert len(agent_mock) == 0


def testAgentZap_whenVpnCountry_RunScan(
    scan_message_link, test_agent_with_vpn, mocker, agent_mock
):
    """Tests running the agent with vpn_country and emitting vulnerabilities."""
    with (pathlib.Path(__file__).parent / "zap-test-output.json").open(
        "r", encoding="utf-8"
    ) as o:
        mock_scan = mocker.patch(
            "agent.zap_wrapper.ZapWrapper.scan", return_value=json.load(o)
        )

        use_vpn_mock = mocker.patch(
            "agent.zap_agent.ZapAgent.use_vpn", return_value=None
        )
        mocker.patch("subprocess.run", return_value=EXEC_COMMAND_OUTPUT)
        test_agent_with_vpn.start()
        test_agent_with_vpn.process(scan_message_link)
        assert mock_scan.is_called_once_with("https://test.ostorlab.co")
        assert use_vpn_mock.call_args_list[0].args[0] == VPN_CONFIG
        assert len(agent_mock) > 0
        assert agent_mock[0].selector == "v3.report.vulnerability"


def testUseVpn_whenConfigFile_callVPN(
    scan_message_link, test_agent_with_vpn, mocker, agent_mock
):
    """Tests set up VPN when call androguard."""
    with (pathlib.Path(__file__).parent / "zap-test-output.json").open(
        "r", encoding="utf-8"
    ) as o:
        mocker.patch("agent.zap_wrapper.ZapWrapper.scan", return_value=json.load(o))

        mocker.patch("subprocess.run", return_value=EXEC_COMMAND_OUTPUT)
        mocker.patch(
            "agent.zap_agent.ZapAgent._save_vpn_and_dns_configurations",
            return_value=None,
        )
        subprocess_mocker = mocker.patch(
            "subprocess.run", return_value=EXEC_COMMAND_OUTPUT
        )

        test_agent_with_vpn.start()
        test_agent_with_vpn.process(scan_message_link)

        assert subprocess_mocker.call_count == 1
        assert subprocess_mocker.call_args_list[0].args[0] == ["wg-quick", "up", "wg0"]


def testAgentZap_whenProxyIsProvided_RunScanWithProxyArguments(
    scan_message_2: message.Message,
    test_agent_with_proxy: zap_agent.ZapAgent,
    mocker: plugin.MockerFixture,
    agent_mock: list[message.Message,],
) -> None:
    """Tests running the agent and emitting vulnerabilities."""
    del agent_mock
    mocker.patch("agent.zap_wrapper.OUTPUT_DIR", ".")
    mock_subprocess = mocker.patch("subprocess.run", return_value=None)
    mocker.patch("builtins.open", new_callable=mock.mock_open())

    test_agent_with_proxy.start()
    test_agent_with_proxy.process(scan_message_2)

    assert mock_subprocess.call_count == 1
    assert mock_subprocess.call_args[0][0] == [
        "/zap/zap-full-scan.py",
        "-d",
        "-t",
        "https://ostorlab.co",
        "-m",
        "10",
        "-z",
        "-config network.connection.httpProxy.enabled=true -config network.connection.httpProxy.host=proxy.ostorlab.co -config network.connection.httpProxy.port=8899",
        "-j",
        "-J",
        mock.ANY,
    ]
