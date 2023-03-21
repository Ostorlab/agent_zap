"""Add scan status API calls."""
import dataclasses
from typing import Any, Dict

from agent import request_sender


@dataclasses.dataclass
class APIConfiguration:
    scanning_engine_endpoint: str
    scanning_engine_auth_token: str
    reporting_engine_endpoint: str
    reporting_engine_auth_token: str


class Error(Exception):
    """Base Custom Error Class."""


class InvalidResponse(Error):
    """Invalid Response Error."""


def add_scan_status(
    url: str, auth_token: str, scan_id: int, key: str, value: str, update_if_exist: bool
) -> Dict[str, Any] | None:
    """Sends an HTTP API request to add or update the status of a specific scan."""
    query = """
        mutation newScanStatus($scanId: Int!, $key:String!, $value: String!, $updateIfExist: Boolean) {
          addScanStatus(scanId: $scanId, key: $key, value: $value, updateIfExist: $updateIfExist) {
            scanStatus {
              key
            }
          }
        }
    """
    variables = {
        "scanId": scan_id,
        "key": key,
        "value": value,
        "updateIfExist": update_if_exist,
    }
    data = {"query": query, "variables": variables}

    return request_sender.make_json_request("POST", url, auth_token, data)
