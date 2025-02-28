"""This file contains tests for helper functions"""

from typing import Any

from ostorlab.assets import domain_name
from ostorlab.agent.mixins import agent_report_vulnerability_mixin as vuln_mixin
import pytest

from agent import helpers


def testComputeDna_withDifferentPackage_returnsDifferentDna() -> None:
    """Ensure that whit different port, ComputeDna returns different DNA."""
    vulnerability_title = "Vulnerability Title Unordered Dict"
    technical_detail = "technical_detail"
    vuln_location_1 = vuln_mixin.VulnerabilityLocation(
        asset=domain_name.DomainName(name="google.com"),
        metadata=[
            vuln_mixin.VulnerabilityLocationMetadata(
                metadata_type=vuln_mixin.MetadataType.URL, value="google.com/contact"
            ),
            vuln_mixin.VulnerabilityLocationMetadata(
                metadata_type=vuln_mixin.MetadataType.PORT, value="8080"
            ),
        ],
    )
    vuln_location_2 = vuln_mixin.VulnerabilityLocation(
        asset=domain_name.DomainName(name="google.com"),
        metadata=[
            vuln_mixin.VulnerabilityLocationMetadata(
                metadata_type=vuln_mixin.MetadataType.URL, value="google.com/contact"
            ),
            vuln_mixin.VulnerabilityLocationMetadata(
                metadata_type=vuln_mixin.MetadataType.PORT, value="8081"
            ),
        ],
    )

    dna_1 = helpers.compute_dna(vulnerability_title, vuln_location_1, technical_detail)
    dna_2 = helpers.compute_dna(vulnerability_title, vuln_location_2, technical_detail)

    assert dna_1 is not None
    assert dna_2 is not None
    assert dna_1 != dna_2
    assert (
        dna_1
        == '{"location": {"domain_name": {"name": "google.com"}, "metadata": [{"type": "PORT", "value": "8080"}, {"type": "URL", "value": "google.com/contact"}]}, "technical_detail": "technical_detail", "title": "Vulnerability Title Unordered Dict"}'
    )
    assert (
        dna_2
        == '{"location": {"domain_name": {"name": "google.com"}, "metadata": [{"type": "PORT", "value": "8081"}, {"type": "URL", "value": "google.com/contact"}]}, "technical_detail": "technical_detail", "title": "Vulnerability Title Unordered Dict"}'
    )


@pytest.mark.parametrize(
    "unordered_dict, expected",
    [
        # Case: Dictionary keys are unordered
        ({"b": 2, "a": 1, "c": 3}, {"a": 1, "b": 2, "c": 3}),
        # Case: Nested dictionaries are also sorted
        ({"z": {"b": 2, "a": 1}, "y": 3}, {"y": 3, "z": {"a": 1, "b": 2}}),
        # Case: Lists inside dictionaries remain unchanged
        ({"list": [3, 1, 2], "key": "value"}, {"key": "value", "list": [1, 2, 3]}),
        # Case: Lists containing dictionaries get sorted by keys
        (
            {"list": [{"b": 2, "a": 1}, {"d": 4, "c": 3}]},
            {"list": [{"a": 1, "b": 2}, {"c": 3, "d": 4}]},
        ),
        # Case: Empty dictionary remains unchanged
        ({}, {}),
        # Case: Dictionary with single key remains unchanged
        ({"a": 1}, {"a": 1}),
    ],
)
def testSortDict_always_returnsSortedDict(
    unordered_dict: dict[str, Any], expected: dict[str, Any]
) -> None:
    """Ensure sort_dict correctly sorts dictionary keys recursively."""
    assert helpers.sort_dict(unordered_dict) == expected
