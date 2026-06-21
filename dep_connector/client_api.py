import json
import logging
from typing import TypeVar

import requests
from pydantic import TypeAdapter, ValidationError

from dep_connector.api_models import (
    COGNITO_AUTH_RESPONSE_ADAPTER,
    DEP_API_ITEMS_ADAPTER,
    DepApiItem,
)
from dep_connector.datasets import DepDataset

logger = logging.getLogger(__name__)
TValidatedPayload = TypeVar("TValidatedPayload")


def _decode_json_response(response: requests.Response, error_message: str) -> object:
    try:
        payload: object = response.json()
    except (json.JSONDecodeError, requests.exceptions.JSONDecodeError) as exception:
        raise ValueError(error_message) from exception
    return payload


def _validate_payload(
    adapter: TypeAdapter[TValidatedPayload],
    payload: object,
    error_message: str,
) -> TValidatedPayload:
    try:
        return adapter.validate_python(payload)
    except ValidationError as exception:
        raise ValueError(error_message) from exception


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
        extended_results: bool,
    ) -> None:
        self.login_endpoint = login_endpoint
        self.api_endpoint = api_endpoint
        self.api_key = api_key
        self.username = username
        self.password = password
        self.client_id = client_id
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
        auth_payload = _decode_json_response(
            response,
            "Unable to decode DEP authentication response",
        )
        auth_response = _validate_payload(
            COGNITO_AUTH_RESPONSE_ADAPTER,
            auth_payload,
            "Invalid DEP authentication response",
        )
        return auth_response.authentication_result.id_token

    def fetch_raw(
        self,
        dataset: DepDataset,
        start_date: str,
        end_date: str,
        token: str | None = None,
    ) -> list[DepApiItem]:
        if token is None:
            token = self.authenticate()
        params: dict[str, str] = {
            "ts": start_date,
            "te": end_date,
            "dset": dataset,
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
        payload = _decode_json_response(response, "Unable to decode DEP API response")
        return _validate_payload(
            DEP_API_ITEMS_ADAPTER, payload, "Invalid DEP API response"
        )
