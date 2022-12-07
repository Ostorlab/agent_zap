"""Unit test for the Zap wrapper class."""
import pytest

from agent import zap_wrapper


def testZapWrapperInit_withIncorrectProfile_raisesValueError():
    """Validates wrapper checks for scan profile value"""
    with pytest.raises(ValueError):
        zap_wrapper.ZapWrapper(scan_profile="random_value")
