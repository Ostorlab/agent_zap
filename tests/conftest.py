"""Pytest fixture for the Zap agent."""

import json
import pathlib
import random

import pytest
from ostorlab.agent import definitions as agent_definitions
from ostorlab.agent.message import message
from ostorlab.runtimes import definitions as runtime_definitions
from ostorlab.utils import definitions as utils_definitions

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

DNS_CONFIG = """
nameserver 127.0.0.11
nameserver 8.8.8.8
nameserver 8.8.4.4
"""


@pytest.fixture
def scan_message():
    """Creates a dummy message of type v3.asset.domain_name to be used by the agent for testing purposes."""
    selector = "v3.asset.domain_name"
    msg_data = {
        "name": "test.ostorlab.co",
    }
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def scan_message_2():
    """Creates a dummy message of type v3.asset.domain_name to be used by the agent for testing purposes."""
    selector = "v3.asset.domain_name"
    msg_data = {
        "name": "ostorlab.co",
    }
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def scan_message_link():
    """Creates a dummy message of type v3.asset.ip.v4 to be used by the agent for testing purposes."""
    selector = "v3.asset.link"
    msg_data = {"url": "https://test.ostorlab.co", "method": "GET"}
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def test_agent():
    with (pathlib.Path(__file__).parent.parent / "ostorlab.yaml").open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        settings = runtime_definitions.AgentSettings(
            key="agent/ostorlab/zap",
            bus_url="NA",
            bus_exchange_topic="NA",
            args=[],
            healthcheck_port=random.randint(5000, 6000),
        )
        return zap_agent.ZapAgent(definition, settings)


@pytest.fixture
def test_agent_with_url_scope():
    with (pathlib.Path(__file__).parent.parent / "ostorlab.yaml").open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        definition.args[3]["value"] = "([a-zA-Z]+://ostorlab.co/?.*)"
        settings = runtime_definitions.AgentSettings(
            key="agent/ostorlab/zap",
            bus_url="NA",
            bus_exchange_topic="NA",
            args=[],
            healthcheck_port=random.randint(5000, 6000),
        )
        return zap_agent.ZapAgent(definition, settings)


@pytest.fixture
def test_agent_with_proxy() -> zap_agent.ZapAgent:
    with (pathlib.Path(__file__).parent.parent / "ostorlab.yaml").open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        definition.args[3]["value"] = "([a-zA-Z]+://ostorlab.co/?.*)"
        settings = runtime_definitions.AgentSettings(
            key="agent/ostorlab/zap",
            bus_url="NA",
            bus_exchange_topic="NA",
            args=[
                utils_definitions.Arg(
                    name="proxy",
                    type="string",
                    value=json.dumps("http://proxy.ostorlab.co:8899").encode(),
                )
            ],
            healthcheck_port=random.randint(5000, 6000),
        )
        return zap_agent.ZapAgent(definition, settings)


@pytest.fixture
def test_agent_with_vpn():
    with (pathlib.Path(__file__).parent.parent / "ostorlab.yaml").open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        definition.args.append(
            {"name": "vpn_config", "type": "string", "value": VPN_CONFIG}
        )
        definition.args.append(
            {"name": "dns_config", "type": "string", "value": DNS_CONFIG}
        )
        definition.args.append(
            {"name": "scan_profile", "type": "string", "value": "full"}
        )

        settings = runtime_definitions.AgentSettings(
            key="agent/ostorlab/zap",
            bus_url="NA",
            bus_exchange_topic="NA",
            args=[],
            healthcheck_port=random.randint(5000, 6000),
        )
        return zap_agent.ZapAgent(definition, settings)


@pytest.fixture()
def zap_missing_headers_output() -> json:
    zap_output_file = (pathlib.Path(__file__).parent / "zap-missing-headers.json").open(
        "r", encoding="utf-8"
    )
    return json.load(zap_output_file)
