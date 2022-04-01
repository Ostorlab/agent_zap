"""Pytest fixture for the Zap agent."""
import pytest

from ostorlab.agent import message


@pytest.fixture
def scan_message():
    """Creates a dummy message of type v3.asset.domain_name to be used by the agent for testing purposes.
    """
    selector = 'v3.asset.domain_name'
    msg_data = {
            'name': 'test.ostorlab.co',
        }
    return message.Message.from_data(selector, data=msg_data)
