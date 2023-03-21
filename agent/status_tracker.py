"""Module responsible for keeping track of agent statuses and persist them."""
import enum

import requests

from agent import apis
from agent import request_sender


class ScanStatusLevel(enum.Enum):
    SUCCESS = "success"
    ERROR = "error"


class StatusTracker:
    """class responsible for sending a request to persist actions status"""

    def __init__(self, api_conf: apis.APIConfiguration, scan_id: int) -> None:
        """Construct necessary attributes of the StatusTracker instance.
        Args:
            api_conf: An instance of `apis.APIConfiguration` containing the API configuration.
            scan_id: the id of the scan.
        """
        self._api_conf = api_conf
        self._scan_id = scan_id

    def add_agent_status(
        self, action_name: str, level: ScanStatusLevel, message: str = ""
    ) -> None:
        """Add a status update of the agent.
        Args:
            action_name: The key for the status.
            level: level of the scan status
            message: The message for the status in case there was an error. Defaults to an empty string.
        """
        try:
            apis.add_scan_status(
                url=self._api_conf.reporting_engine_endpoint,
                auth_token=self._api_conf.reporting_engine_auth_token,
                scan_id=self._scan_id,
                key=f"agent__download_android__{action_name}__{level.name}",
                value=message,
                update_if_exist=False,
            )
        except (
            requests.ConnectionError,
            requests.HTTPError,
            requests.Timeout,
            request_sender.AuthenticationError,
        ):
            pass

    def report_scan_as_failing(self, reason: str) -> None:
        """Add a status of the state of the scan.

        Args:
            reason: message describing the state of the scan.
        """
        apis.add_scan_status(
            url=self._api_conf.reporting_engine_endpoint,
            auth_token=self._api_conf.reporting_engine_auth_token,
            scan_id=self._scan_id,
            key="progress",
            value="error",
            update_if_exist=False,
        )
        apis.add_scan_status(
            url=self._api_conf.reporting_engine_endpoint,
            auth_token=self._api_conf.reporting_engine_auth_token,
            scan_id=self._scan_id,
            key="message_status",
            value=reason,
            update_if_exist=False,
        )
