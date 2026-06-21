from unittest.mock import Mock, patch

import pytest
import requests

from dep_connector.client_api import DepClient
from dep_connector.datasets import DepDataset


def _client(*, extended_results: bool = True) -> DepClient:
    return DepClient(
        login_endpoint="https://login.example.test",
        api_endpoint="https://api.example.test/leaks",
        api_key="api-key",
        username="user",
        password="password",
        client_id="client-id",
        extended_results=extended_results,
    )


def test_authenticate_returns_cognito_id_token() -> None:
    response = Mock()
    response.json.return_value = {"AuthenticationResult": {"IdToken": "token-123"}}
    with patch("dep_connector.client_api.requests.post", return_value=response) as post:
        assert _client().authenticate() == "token-123"
    response.raise_for_status.assert_called_once()
    post.assert_called_once_with(
        "https://login.example.test",
        headers={
            "Content-Type": "application/x-amz-json-1.1",
            "X-Amz-Target": "AWSCognitoIdentityProviderService.InitiateAuth",
        },
        json={
            "AuthParameters": {"USERNAME": "user", "PASSWORD": "password"},
            "AuthFlow": "USER_PASSWORD_AUTH",
            "ClientId": "client-id",
        },
        timeout=30,
    )


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"AuthenticationResult": {}},
        {"AuthenticationResult": {"IdToken": ""}},
        {"AuthenticationResult": {"IdToken": 42}},
        [],
    ],
)
def test_authenticate_rejects_missing_or_invalid_id_token(payload: object) -> None:
    response = Mock()
    response.json.return_value = payload

    with (
        patch("dep_connector.client_api.requests.post", return_value=response),
        pytest.raises(ValueError, match="Invalid DEP authentication response"),
    ):
        _client().authenticate()


def test_authenticate_wraps_invalid_json_response() -> None:
    response = Mock()
    response.json.side_effect = requests.exceptions.JSONDecodeError("bad", "{}", 0)

    with (
        patch("dep_connector.client_api.requests.post", return_value=response),
        pytest.raises(ValueError, match="decode DEP authentication response"),
    ):
        _client().authenticate()


def test_fetch_raw_returns_api_items_and_request_parameters() -> None:
    response = Mock()
    response.json.return_value = [
        {"date": "2026-03-27", "hashid": "abc", "victim": "Victim"}
    ]
    with patch("dep_connector.client_api.requests.get", return_value=response) as get:
        items = _client(extended_results=False).fetch_raw(
            dataset=DepDataset.EXTORTION,
            start_date="2026-03-01",
            end_date="2026-03-27",
            token="token-123",
        )

    assert items == [{"date": "2026-03-27", "hashid": "abc", "victim": "Victim"}]
    response.raise_for_status.assert_called_once()
    get.assert_called_once_with(
        "https://api.example.test/leaks",
        headers={"X-Api-Key": "api-key", "Authorization": "token-123"},
        params={
            "ts": "2026-03-01",
            "te": "2026-03-27",
            "dset": DepDataset.EXTORTION,
            "full": "true",
        },
        timeout=60,
    )


def test_fetch_raw_adds_extended_parameter_when_enabled() -> None:
    response = Mock()
    response.json.return_value = []
    with patch("dep_connector.client_api.requests.get", return_value=response) as get:
        _client().fetch_raw(
            dataset=DepDataset.DDOS,
            start_date="2026-03-01",
            end_date="2026-03-27",
            token="token-123",
        )

    assert get.call_args.kwargs["params"]["extended"] == "true"


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"items": []},
        [42],
        ["not an object"],
    ],
)
def test_fetch_raw_rejects_invalid_api_payload_shape(payload: object) -> None:
    response = Mock()
    response.json.return_value = payload

    with (
        patch("dep_connector.client_api.requests.get", return_value=response),
        pytest.raises(ValueError, match="DEP API response"),
    ):
        _client().fetch_raw(
            dataset=DepDataset.EXTORTION,
            start_date="2026-03-01",
            end_date="2026-03-27",
            token="token-123",
        )


def test_fetch_raw_wraps_invalid_json_response() -> None:
    response = Mock()
    response.json.side_effect = requests.exceptions.JSONDecodeError("bad", "{}", 0)

    with (
        patch("dep_connector.client_api.requests.get", return_value=response),
        pytest.raises(ValueError, match="decode DEP API response"),
    ):
        _client().fetch_raw(
            dataset=DepDataset.EXTORTION,
            start_date="2026-03-01",
            end_date="2026-03-27",
            token="token-123",
        )
