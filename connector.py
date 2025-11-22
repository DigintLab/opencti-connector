import json
import os
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import unquote

import requests
import yaml
from pycti import (  # type: ignore[import-untyped]
    OpenCTIConnectorHelper,
    get_config_variable,
)


class DepConnector:
    def __init__(self) -> None:
        config = self._load_config()
        self.helper = OpenCTIConnectorHelper(config)

        self.interval = int(
            get_config_variable(
                "CONNECTOR_RUN_INTERVAL",
                ["connector", "interval"],
                config,
                default=3600,
            )
        )
        self.lookback_days = int(
            get_config_variable(
                "DEP_LOOKBACK_DAYS",
                ["dep", "lookback_days"],
                config,
                default=7,
            )
        )
        self.api_key = get_config_variable("DEP_API_KEY", ["dep", "api_key"], config)
        self.username = get_config_variable("DEP_USERNAME", ["dep", "username"], config)
        self.password = get_config_variable("DEP_PASSWORD", ["dep", "password"], config)
        self.client_id = get_config_variable(
            "DEP_CLIENT_ID",
            ["dep", "client_id"],
            config,
            default="",
        )
        if not self.client_id:
            error = "DEP client ID must be provided via configuration"
            raise ValueError(error)
        self.login_endpoint = get_config_variable(
            "DEP_LOGIN_ENDPOINT",
            ["dep", "login_endpoint"],
            config,
            default="https://cognito-idp.eu-west-1.amazonaws.com/",
        )
        self.api_endpoint = get_config_variable(
            "DEP_API_ENDPOINT",
            ["dep", "api_endpoint"],
            config,
            default="https://api.eu-ep1.doubleextortion.com/v1/dbtr/privlist",
        )
        self.dataset = get_config_variable(
            "DEP_DSET",
            ["dep", "dset"],
            config,
            default="ext",
        )
        self.extended_results = self._get_boolean_config(
            get_config_variable(
                "DEP_EXTENDED_RESULTS",
                ["dep", "extended_results"],
                config,
                default=True,
            )
        )
        self.enable_site_indicator = self._get_boolean_config(
            get_config_variable(
                "DEP_ENABLE_SITE_INDICATOR",
                ["dep", "enable_site_indicator"],
                config,
                default=True,
            )
        )
        self.enable_hash_indicator = self._get_boolean_config(
            get_config_variable(
                "DEP_ENABLE_HASH_INDICATOR",
                ["dep", "enable_hash_indicator"],
                config,
                default=True,
            )
        )

    @staticmethod
    def _load_config() -> dict[str, Any]:
        # Resolve config path from environment variable or fallback to config.yml next to this file
        config_path = os.environ.get(
            "OPENCTI_CONFIG_FILE",
            Path(__file__).resolve().parent / "config.yml",
        )
        config_path = Path(config_path)
        if config_path.exists():
            with config_path.open(encoding="utf-8") as config_file:
                return yaml.safe_load(config_file) or {}
        return {}

    @staticmethod
    def _get_boolean_config(s: str) -> bool:
        val = s.lower()
        if val in ("y", "yes", "t", "true", "on", "1"):
            return True
        if val in ("n", "no", "f", "false", "off", "0"):
            return False
        error = f"Invalid truth value: {s}"
        raise ValueError(error)

    def _authenticate(self) -> str:
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
        except ValueError as e:
            error = "Unable to retrieve IdToken from authentication response"
            raise ValueError(error) from e
        return token

    def _fetch_data(self, start: datetime, end: datetime) -> list[dict[str, Any]]:
        token = self._authenticate()
        params = {
            "ts": start.strftime("%Y-%m-%d"),
            "te": end.strftime("%Y-%m-%d"),
            "dset": self.dataset,
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

        if isinstance(data, list):
            return data
        self.helper.log_warning("DEP API returned unexpected payload type")
        return []

    def _create_victim_identity(self, item: dict[str, Any]) -> dict[str, Any] | None:
        victim_name = item.get("victim")
        if not victim_name:
            return None

        external_references = []
        if item.get("annLink"):
            external_references.append(
                {
                    "source_name": "dep",
                    "url": item["annLink"],
                    "description": item.get("annTitle"),
                }
            )
        if item.get("site") and item.get("site") != item.get("annLink"):
            external_references.append(
                {
                    "source_name": "victim-site",
                    "url": (
                        f"https://{item['site']}"
                        if not item["site"].startswith("http")
                        else item["site"]
                    ),
                }
            )

        description_parts = []
        if item.get("sector"):
            description_parts.append(f"Industry sector: {item['sector']}")
        if item.get("revenue"):
            description_parts.append(f"Reported revenue: {item['revenue']}")
        description = "\n".join(description_parts) or None

        country = item.get("country")
        location_id = self._resolve_location(country) if country else None

        return self.helper.api.identity.create(
            type="Organization",
            name=victim_name,
            description=description,
            confidence=self.helper.connect_confidence_level,
            external_references=external_references,
            x_opencti_location=location_id,
        )

    def _create_intrusion_set(self, item: dict[str, Any]) -> dict[str, Any] | None:
        actor_name = item.get("actor")
        if not actor_name:
            return None
        return self.helper.api.intrusion_set.create(
            name=actor_name,
            description="Threat actor",
            aliases=[actor_name],
            confidence=self.helper.connect_confidence_level,
        )

    def _create_incident(
        self,
        item: dict[str, Any],
        victim: dict[str, Any] | None,
    ) -> dict[str, Any] | None:
        victim_name = victim["name"] if victim else item.get("victim", "Unknown victim")
        incident_name = f"DEP announcement - {victim_name}"
        description = item.get("annDescription") or item.get("description")
        if description:
            description = unquote(description)
        announcement_date = item.get("date")
        first_seen = None
        if announcement_date:
            try:
                first_seen = datetime.fromisoformat(announcement_date).isoformat()
            except ValueError:
                first_seen = announcement_date

        external_reference = {"source_name": "dep"}
        if item.get("annLink"):
            external_reference["url"] = item["annLink"]
        elif item.get("site"):
            site = item["site"]
            external_reference["url"] = (
                site if site.startswith("http") else f"https://{site}"
            )
        if item.get("annTitle"):
            external_reference["description"] = item["annTitle"]

        return self.helper.api.incident.create(
            name=incident_name,
            description=description,
            first_seen=first_seen,
            created=first_seen,
            confidence=self.helper.connect_confidence_level,
            external_references=[external_reference],
        )

    def _create_site_indicator(self, item: dict[str, Any]) -> dict[str, Any] | None:
        if not self.enable_site_indicator:
            return None
        domain = item.get("victimDomain") or item.get("site")
        if not domain:
            return None
        domain = domain.lower().strip()
        domain = domain.replace("https://", "").replace("http://", "")
        if not domain:
            return None
        return self.helper.api.indicator.create(
            name=f"Domain associated with {item.get('victim', 'unknown victim')}",
            description="Victim domain",
            pattern_type="stix",
            pattern=f"[domain-name:value = '{domain}']",
            confidence=self.helper.connect_confidence_level,
            valid_from=datetime.now(UTC).isoformat(),
        )

    def _create_hash_indicator(self, item: dict[str, Any]) -> dict[str, Any] | None:
        if not self.enable_hash_indicator:
            return None
        hash_value = item.get("hashid")
        if not hash_value:
            return None
        hash_value = hash_value.lower().strip()
        if not hash_value:
            return None
        hash_type = self._detect_hash_type(hash_value)
        if not hash_type:
            return None
        return self.helper.api.indicator.create(
            name=f"Announcement hash for {item.get('victim', 'unknown victim')}",
            description="Hash identifier for tracking",
            pattern_type="stix",
            pattern=f"[file:hashes.'{hash_type}' = '{hash_value}']",
            confidence=self.helper.connect_confidence_level,
            valid_from=datetime.now(UTC).isoformat(),
        )

    @staticmethod
    def _detect_hash_type(hash_value: str) -> str | None:
        length_to_type = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}
        return length_to_type.get(len(hash_value))

    def _resolve_location(self, country: str) -> str | None:
        if not country:
            return None
        try:
            result = self.helper.api.location.read(
                filters=[{"key": "x_opencti_aliases", "values": [country]}]
            )
            if result:
                return str(result.get("id"))
        except Exception as error:  # pylint: disable=broad-except
            self.helper.log_warning(
                f"Unable to resolve location for {country}: {error}"
            )
        return None

    def _link_entities(
        self,
        victim: dict[str, Any] | None,
        incident: dict[str, Any] | None,
        indicators: list[dict[str, Any]],
    ) -> None:
        if not incident:
            return
        incident_id = incident.get("id")
        if victim:
            self.helper.api.stix_core_relationship.create(
                relationship_type="targets",
                source_ref=incident_id,
                target_ref=victim["id"],
                confidence=self.helper.connect_confidence_level,
            )
        for indicator in indicators:
            try:
                self.helper.api.stix_core_relationship.create(
                    relationship_type="indicates",
                    source_ref=indicator["id"],
                    target_ref=incident_id,
                    confidence=self.helper.connect_confidence_level,
                )
            except Exception as error:  # pylint: disable=broad-except
                self.helper.log_warning(
                    f"Unable to create indicates relationship for indicator {indicator.get('id')}: {error}"
                )

    def _process_item(self, item: dict[str, Any]) -> None:
        victim = self._create_victim_identity(item)
        # Intrusion set creation is intentionally disabled because datasets may
        # include non-adversarial actors.
        incident = self._create_incident(item, victim)

        indicators: list[dict[str, Any]] = []
        site_indicator = self._create_site_indicator(item)
        if site_indicator:
            indicators.append(site_indicator)
        hash_indicator = self._create_hash_indicator(item)
        if hash_indicator:
            indicators.append(hash_indicator)

        self._link_entities(victim, incident, indicators)

    def _run_cycle(self) -> None:
        current_state = self.helper.get_state() or {}
        last_run_str = current_state.get("last_run")
        now = datetime.now(UTC)
        if last_run_str:
            try:
                start = datetime.fromisoformat(last_run_str)
            except ValueError:
                start = now - timedelta(days=self.lookback_days)
        else:
            start = now - timedelta(days=self.lookback_days)
        end = now

        self.helper.log_info(
            f"Fetching DEP data from {start.date().isoformat()} to {end.date().isoformat()}"
        )

        try:
            items = self._fetch_data(start, end)
        except Exception as error:  # pylint: disable=broad-except
            self.helper.log_error(f"Failed to fetch DEP data: {error}")
            return

        self.helper.log_info(f"Received {len(items)} entries from DEP API")

        for item in items:
            try:
                self._process_item(item)
            except Exception as error:  # pylint: disable=broad-except
                self.helper.log_error(
                    f"Failed to process DEP item for victim {item.get('victim')}: {error}"
                )

        self.helper.log_info("Persisting connector state")
        self.helper.set_state({"last_run": end.isoformat()})
        self.helper.log_info("DEP run completed")

    def run(self) -> None:
        self.helper.log_info("Starting DEP connector")
        while True:
            self._run_cycle()
            time.sleep(self.interval)


if __name__ == "__main__":
    connector = DepConnector()
    connector.run()
