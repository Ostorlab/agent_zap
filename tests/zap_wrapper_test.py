"""Unit test for the Zap wrapper class."""
import pytest
import subprocess

from agent import zap_wrapper
import tenacity

from pytest_mock import plugin


def testZapWrapperInit_withIncorrectProfile_raisesValueError():
    """Validates wrapper checks for scan profile value"""
    with pytest.raises(ValueError):
        zap_wrapper.ZapWrapper(scan_profile="random_value")


def testZapWrapperScan_withTimeoutException_raisesValueError(mocker: plugin.MockerFixture,):
    """Validates wrapper timeout logic"""
    run_mock = mocker.patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="", timeout=0.1))
    mocker.patch.object(zap_wrapper, "OUTPUT_DIR", "/tmp")
    with pytest.raises(tenacity.RetryError):
        zap = zap_wrapper.ZapWrapper(scan_profile="baseline")
        zap.scan(target="https://dummy.com")
    assert run_mock.call_count == 5
