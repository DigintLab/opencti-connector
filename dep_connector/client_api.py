import json
import logging
from typing import Any

import requests

logger = logging.getLogger(__name__)


class DepClient:
    def __init__(
        self,
        *,
        login_endpoint: str,
        api_endpoint: str,
        api_key: str | None,
        username: str | None,
        password: str | None,
        client_id: str,
        dataset: str,
        extended_results: bool,
    ) -> None:
        self.login_endpoint = login_endpoint
        self.api_endpoint = api_endpoint
        self.api_key = api_key
        self.username = username
        self.password = password
        self.client_id = client_id
        self.dataset = dataset
        self.extended_results = extended_results

    def authenticate(self) -> str:
        headers = {
            "Content-Type": "application/x-amz-json-1.1",
            "X-Amz-Target": "AWSCognitoIdentityProviderService.InitiateAuth",
        }
        payload = {
            "AuthParameters": {"USERNAME": self.username, "PASSWORD": self.password},
            "AuthFlow": "USER_PASSWORD_AUTH",
            "ClientId": self.client_id,
        }
        response = requests.post(
            self.login_endpoint,
            headers=headers,
            json=payload,
            timeout=30,
        )
        response.raise_for_status()
        data = response.json()
        try:
            token = str(data.get("AuthenticationResult").get("IdToken"))
        except Exception as e:
            error = "Unable to retrieve IdToken from authentication response"
            raise ValueError(error) from e
        return token

    def fetch_raw(
        self,
        start_date: str,
        end_date: str,
    ) -> list[dict[str, Any]]:
        token = self.authenticate()
        params: dict[str, str] = {
            "ts": start_date,
            "te": end_date,
            "dset": self.dataset,
            "full": "true",
        }
        if self.extended_results:
            params["extended"] = "true"

        headers = {
            "X-Api-Key": self.api_key,
            "Authorization": token,
        }

        response = requests.get(
            self.api_endpoint,
            headers=headers,
            params=params,
            timeout=60,
        )
        response.raise_for_status()
        try:
            data = response.json()
        except json.JSONDecodeError as exception:
            message = "Unable to decode DEP API response"
            raise ValueError(message) from exception

        if not isinstance(data, list):
            logger.warning("DEP API returned unexpected payload type")
            return []

        result: list[dict[str, Any]] = []
        for index, item in enumerate(data):
            if isinstance(item, dict):
                result.append(item)
            else:
                logger.warning(
                    "Skipping DEP item at index %d: expected object, got %s",
                    index,
                    type(item).__name__,
                )
        return result
