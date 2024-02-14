"""Unit test for the Zap wrapper class."""
import pytest
import subprocess

from agent import zap_wrapper
import tenacity

from pytest_mock import plugin
from unittest import mock


def testZapWrapperInit_withIncorrectProfile_raisesValueError():
    """Validates wrapper checks for scan profile value"""
    with pytest.raises(ValueError):
        zap_wrapper.ZapWrapper(scan_profile="random_value")


def testZapWrapperScan_withTimeoutException_raisesValueError(
    mocker: plugin.MockerFixture,
):
    """Validates wrapper timeout logic"""
    run_mock = mocker.patch(
        "subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="", timeout=0.1)
    )
    mocker.patch.object(zap_wrapper, "OUTPUT_DIR", "/tmp")
    with pytest.raises(tenacity.RetryError):
        zap = zap_wrapper.ZapWrapper(scan_profile="baseline")
        zap.scan(target="https://dummy.com")
    assert run_mock.call_count == 5


def testZapWrapperScan_whenProxyNoSchema_shouldNotCallWithProxy(
    mocker: plugin.MockerFixture,
) -> None:
    """Validates wrapper handles proxy with no schema"""
    run_mock = mocker.patch("subprocess.run")
    mocker.patch.object(zap_wrapper, "OUTPUT_DIR", "/tmp")
    zap = zap_wrapper.ZapWrapper(
        scan_profile="baseline", proxy="http://proxynoschema.com:8080"
    )

    zap.scan(target="https://dummy.com")

    assert run_mock.call_count == 1
    assert run_mock.call_args[0][0] == [
        "/zap/zap-baseline.py",
        "-d",
        "-t",
        "https://dummy.com",
        "-z",
        "-config network.connection.httpProxy.enabled=true -config "
        "network.connection.httpProxy.host=proxynoschema.com -config "
        "network.connection.httpProxy.port=8080",
        "-j",
        "-J",
        mock.ANY,
    ]
