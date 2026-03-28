import json
import logging
from enum import StrEnum
from typing import TypeAlias

import requests

logger = logging.getLogger(__name__)

JsonPrimitive: TypeAlias = str | int | float | bool | None
JsonValue: TypeAlias = JsonPrimitive | list["JsonValue"] | dict[str, "JsonValue"]
DepApiItem: TypeAlias = dict[str, JsonValue]


class DepDataset(StrEnum):
    EXTORTION = "ext"
    PRIVACY = "prv"
    OPENNEWS = "nws"
    VANDALISM = "vnd"
    DDOS = "dds"
    FORUM = "frm"

    @classmethod
    def _missing_(cls, value: object) -> "DepDataset | None":
        if not isinstance(value, str):
            return None
        return DATASET_ALIASES.get(value)


DATASET_ALIASES: dict[str, DepDataset] = {
    "extortion": DepDataset.EXTORTION,
    "privacy": DepDataset.PRIVACY,
    "opennews": DepDataset.OPENNEWS,
    "news": DepDataset.OPENNEWS,
    "vandalism": DepDataset.VANDALISM,
    "ddos": DepDataset.DDOS,
    "forum": DepDataset.FORUM,
}


def dataset_alias_summary() -> str:
    aliases_by_dataset: dict[DepDataset, list[str]] = {}
    for alias, dataset in DATASET_ALIASES.items():
        aliases_by_dataset.setdefault(dataset, []).append(alias)
    groups = ["/".join(aliases_by_dataset[dataset]) for dataset in DepDataset]
    return ", ".join(group for group in groups if group)


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
        auth_payload: dict[str, dict[str, str]] = response.json()
        token = auth_payload["AuthenticationResult"]["IdToken"]
        if not token:
            error = "Unable to retrieve IdToken from authentication response"
            raise ValueError(error)
        return token

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
        try:
            payload: list[DepApiItem] = response.json()
        except json.JSONDecodeError as exception:
            message = "Unable to decode DEP API response"
            raise ValueError(message) from exception
        return payload
