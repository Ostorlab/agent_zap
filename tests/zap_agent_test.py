"""Unittests for nuclei class."""
import pathlib
from unittest import mock

from ostorlab.agent import definitions as agent_definitions
from ostorlab.agent.mixins import agent_report_vulnerability_mixin
from ostorlab.runtimes import definitions as runtime_definitions

from agent import zap_agent


@mock.patch('agent.agent.OUTPUT_PATH', './tests/result_nuclei.json')
def testAgentZap_whenDomainNameAsset_RunScan(scan_message, mocker):
    """Tests running the agent and parsing the json output."""
    with (pathlib.Path(__file__).parent / 'ostorlab.yaml').open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        settings = runtime_definitions.AgentSettings(
            key='agent/ostorlab/zap',
            bus_url='NA',
            bus_exchange_topic='NA',
            args=[],
            healthcheck_port=5301)
        mocker.patch('subprocess.run', return_value=None)
        mock_report_vulnerability = mocker.patch('agent.agent.AgentNuclei.report_vulnerability', return_value=None)
        test_agent = zap_agent.ZapAgent(definition, settings)
        test_agent.process(scan_message)
        mock_report_vulnerability.assert_called_once()
        assert mock_report_vulnerability.call_args.kwargs['entry'].cvss_v3_vector \
               == 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'
        assert """Matched : `ats` at""" in mock_report_vulnerability.call_args.kwargs['technical_detail']
        assert 'Author' not in mock_report_vulnerability.call_args.kwargs['technical_detail']
        assert mock_report_vulnerability.call_args.kwargs['risk_rating'] == agent_report_vulnerability_mixin.RiskRating.INFO