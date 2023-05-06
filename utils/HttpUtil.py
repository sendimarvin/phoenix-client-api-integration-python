import json
import logging
import requests
import urllib3
from typing import Dict

# Disable insecure SSL warning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

def post_http_request(resource_url: str, headers: Dict[str, str], data: str) -> str:
    logger.info(f"http outgoing request body {data}")
    logger.info(f"http outgoing request url {resource_url}")
    response = requests.post(
        url=resource_url,
        headers={
            **headers,
            "Accept": "application/json",
            "Content-type": "application/json",
        },
        data=data,
        verify=False
    )
    response.raise_for_status()
    response_data = response.json()
    logger.info(f"http response code {response.status_code}")
    logger.info(f"http response body {response_data}")
    return json.dumps(response_data)

def get_http_request(resource_url: str, headers: Dict[str, str]) -> str:
    logger.info(f"http outgoing request url {resource_url}")
    response = requests.get(
        url=resource_url,
        headers={
            **headers,
            "Accept": "application/json",
            "Content-type": "application/json",
        },
        verify=False
    )
    response.raise_for_status()
    response_data = response.json()
    logger.info(f"http response code {response.status_code}")
    logger.info(f"http response body {response_data}")
    return json.dumps(response_data)
