"""Module responsible for sending HTTP requests"""
import logging
from typing import Any, Dict, Optional
import datetime

import requests
import tenacity

logger = logging.getLogger(__name__)


class Error(Exception):
    """Base Custom Error Class."""


class AuthenticationError(Error):
    """Authentication Error."""


class APICallError(Error):
    """API call was 200, but had errors in the response."""


PLAY_STORE_REQUEST_TIMEOUT = datetime.timedelta(minutes=1)


@tenacity.retry(
    stop=tenacity.stop.stop_after_attempt(3),
    wait=tenacity.wait.wait_fixed(2),
    retry=tenacity.retry_if_exception_type(),
    retry_error_callback=lambda retry_state: retry_state.outcome.result()
    if retry_state.outcome is not None
    else None,
)
def make_json_request(
    method: str, path: str, auth_token: str, data: Optional[Dict[str, Any]] = None
) -> Dict[str, Any] | None:
    """Sends a json HTTP request.

    Args:
        method: The method to use to send the request.
        path: The url to send the request to.
        auth_token: The token to use for authentication.
        data: Data to send in the body of the request.

    Raises:
        AuthenticationError: When the provided token could not be used to authenticate.
        APICallError: When an error was encountered when making the request.

    Returns:
        The response of the request.
    """
    headers = {"Authorization": f"Token {auth_token}"}
    logger.debug("request %s %s %s", method, path, data)
    response = requests.request(method, path, json=data, headers=headers, timeout=10)
    if response.status_code not in [200, 201, 204]:
        logger.error("received %i %s", response.status_code, response.content)
        raise AuthenticationError(response.reason)
    if "errors" in response.json():
        logger.error("API call encountered following errors: %s", response.reason)
        raise APICallError(str(response.reason))
    if response.status_code == 200:
        res: Dict[str, Any] = response.json()
        return res

    return None


def play_store_get_request(dev_id: str, country_code: str) -> bytes:
    """Makes a GET request to the Google Play Store.

    Args:
        dev_id: developer id
        country_code: two-letter code for country in caps

    Returns: The response of the request in bytes.

    Raises:
        ValueError: When the Developer ID wasn't found.

    """

    url_params = {"id": dev_id, "gl": country_code}

    url = "https://play.google.com/store/apps/developer"
    alternative_url = "https://play.google.com/store/apps/dev"
    resp = requests.get(
        url, params=url_params, timeout=PLAY_STORE_REQUEST_TIMEOUT.seconds
    )
    if resp.status_code == 404:
        resp = requests.get(
            alternative_url,
            params=url_params,
            timeout=PLAY_STORE_REQUEST_TIMEOUT.seconds,
        )
        if resp.status_code == 404:
            raise ValueError(
                f"Devlopper ID: {dev_id} not found\n{url}\n{alternative_url}"
            )
    return resp.content


def play_store_post_request(
    token: str, country_code: str, lang: str = "us", num: int = 100
) -> bytes:
    """Makes a POST request to the Google Play Store.

    Args:
        token: the token parsed in the first page
        country_code: two-letter code for country in caps
        lang: language for the page
        num: number of apps you want to be retrieved

    Returns: The response of the request in bytes

    """

    rpc_id = "qnKhOb"

    # To understand the meaning of the different params, see reference:
    # https://kovatch.medium.com/deciphering-google-batchexecute-74991e4e446c

    params = {
        "rpcids": rpc_id,
        "f.sid": "-697906427155521722",
        "bl": "boq_playuiserver_20190903.08_p0",
        "hl": lang,
        "gl": country_code,
        "authuser&soc-app": "121",
        "soc-platform": "1",
        "soc-device": "1",
        "_reqid": "1065213",
    }

    url = "https://play.google.com/_/PlayStoreUi/data/batchexecute"

    body = f'f.req=[[["{rpc_id}","[[null,[[10,[10,{num}]],true,null, \
    [96,27,4,8,57,30,110,79,11,16,49,1,3,9,12,104,55,56,51,10,34,77]],null,\\"{token}\\"]]",null,"generic"]]]'

    header = {"Content-Type": "application/x-www-form-urlencoded;charset=UTF-8"}
    resp = requests.post(
        url,
        body,
        headers=header,
        params=params,
        timeout=PLAY_STORE_REQUEST_TIMEOUT.seconds,
    )
    if resp.status_code == 404:
        raise ValueError("The POST failed, the token is probably wrong")
    return resp.content
