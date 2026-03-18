import json
import os
from datetime import UTC, datetime, timedelta
from datetime import date as dt_date
from enum import StrEnum
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit
from uuid import NAMESPACE_URL, uuid5

import pycti  # type: ignore[import-untyped]
import requests
import yaml
from pydantic import ConfigDict, Field, field_validator
from pydantic.dataclasses import dataclass
from stix2 import TLP_AMBER  # type: ignore[import-untyped]
from stix2 import v21 as stix2


class AnnouncementType(StrEnum):
    AI = "AI"
    CUSTOMERS = "CUSTOMERS"
    DEFENSE = "DEFENSE"
    EMPLOYEES = "EMPLOYEES"
    FINANCIAL = "FINANCIAL"
    INTERNAL = "INTERNAL"
    IP = "IP"
    MEDICAL = "MEDICAL"
    PARTNERS = "PARTNERS"
    PII = "PII"
    SENSITIVES = "SENSITIVES"


class PrimaryObject(StrEnum):
    REPORT = "report"
    INCIDENT = "incident"


@dataclass(config=ConfigDict(extra="allow", frozen=True))
class LeakRecord:
    date: dt_date
    hashid: str

    victim: str | None = None
    sector: str | None = None
    actor: str | None = None
    country: str | None = None

    revenue: str | None = None

    site: str | None = None
    ann_link: str | None = Field(default=None, alias="annLink")
    ann_title: str | None = Field(default=None, alias="annTitle")
    victim_domain: str | None = Field(default=None, alias="victimDomain")
    ann_description: str | None = Field(default=None, alias="annDescription")

    announcement_types: list[AnnouncementType] = Field(
        default_factory=list,
        alias="annDataTypes",
    )

    @field_validator("ann_link")
    @classmethod
    def annlink_repair_common_scrape_bug(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if v.startswith("https//"):
            return "https://" + v[len("https//") :]
        if v.startswith("http//"):
            return "http://" + v[len("http//") :]
        return v

    @field_validator("site", "victim_domain")
    @classmethod
    def strip_optional_text(cls, v: str | None) -> str | None:
        if v is None:
            return None
        stripped = v.strip()
        return stripped or None

    @staticmethod
    def _normalize_domain(value: str | None) -> str | None:
        if not value:
            return None
        parsed = urlsplit(value if "://" in value else f"https://{value}")
        domain = parsed.hostname or ""
        normalized = domain.strip().lower()
        return normalized or None

    @property
    def indicator_domain(self) -> str | None:
        return self._normalize_domain(self.victim_domain) or self._normalize_domain(
            self.site
        )

    @field_validator("sector", "actor", "country")
    @classmethod
    def normalize_named_field(cls, v: str | None) -> str | None:
        if v is None:
            return None
        normalized = " ".join(v.split()).strip()
        if not normalized:
            return None
        if normalized.lower() in {"n/a", "none"}:
            return None
        return normalized


class DepConnector:
    GENERIC_ACTOR_VALUES = frozenset(
        {
            "unknown",
            "unk",
            "anonymous",
            "unattributed",
            "undisclosed",
            "not disclosed",
            "not-disclosed",
            "ransomware group",
            "ransomware gang",
            "threat actor",
            "attacker",
        }
    )

    def __init__(self) -> None:
        config = self._load_config()
        self.helper = pycti.OpenCTIConnectorHelper(config)
        self.label_value = "DigIntLab"
        self.author_identity = stix2.Identity(
            id=pycti.Identity.generate_id(
                self.label_value, identity_class="organization"
            ),
            name=self.label_value,
            description="We Track and Monitor the Cyber Space",
            contact_information="https://doubleextortion.com/",
            identity_class="organization",
            object_marking_refs=[TLP_AMBER],
        )
        self._current_work_id: str | None = None

        self.interval = pycti.get_config_variable(
            "CONNECTOR_RUN_INTERVAL",
            ["connector", "interval"],
            config,
            default=3600,
            isNumber=True,
        )
        self.lookback_days = pycti.get_config_variable(
            "DEP_LOOKBACK_DAYS",
            ["dep", "lookback_days"],
            config,
            default=7,
            isNumber=True,
        )
        self.overlap_hours = pycti.get_config_variable(
            "DEP_OVERLAP_HOURS",
            ["dep", "overlap_hours"],
            config,
            default=72,
            isNumber=True,
        )
        self.confidence = pycti.get_config_variable(
            "DEP_CONFIDENCE", ["dep", "confidence"], config, default=70, isNumber=True
        )
        self.api_key = pycti.get_config_variable(
            "DEP_API_KEY", ["dep", "api_key"], config
        )
        self.username = pycti.get_config_variable(
            "DEP_USERNAME", ["dep", "username"], config
        )
        self.password = pycti.get_config_variable(
            "DEP_PASSWORD", ["dep", "password"], config
        )
        self.client_id = pycti.get_config_variable(
            "DEP_CLIENT_ID", ["dep", "client_id"], config, default=""
        )
        if not self.client_id:
            error = "DEP client ID must be provided via configuration"
            raise ValueError(error)
        self.login_endpoint = pycti.get_config_variable(
            "DEP_LOGIN_ENDPOINT",
            ["dep", "login_endpoint"],
            config,
            default="https://cognito-idp.eu-west-1.amazonaws.com/",
        )

        self.api_endpoint = pycti.get_config_variable(
            "DEP_API_ENDPOINT",
            ["dep", "api_endpoint"],
            config,
            default="https://api.eu-ep1.doubleextortion.com/v1/dbtr/privlist",
        )
        self.dataset = pycti.get_config_variable(
            "DEP_DSET",
            ["dep", "dset"],
            config,
            default="ext",
        )
        self.extended_results = pycti.get_config_variable(
            "DEP_EXTENDED_RESULTS",
            ["dep", "extended_results"],
            config,
            default=True,
        )
        self.enable_site_indicator = pycti.get_config_variable(
            "DEP_ENABLE_SITE_INDICATOR",
            ["dep", "enable_site_indicator"],
            config,
            default=True,
        )

        self.enable_hash_indicator = pycti.get_config_variable(
            "DEP_ENABLE_HASH_INDICATOR",
            ["dep", "enable_hash_indicator"],
            config,
            default=True,
        )
        self.skip_empty_victim = pycti.get_config_variable(
            "DEP_SKIP_EMPTY_VICTIM",
            ["dep", "skip_empty_victim"],
            config,
            default=True,
        )
        self.create_sector_identities = pycti.get_config_variable(
            "DEP_CREATE_SECTOR_IDENTITIES",
            ["dep", "create_sector_identities"],
            config,
            default=True,
        )
        self.create_intrusion_sets = pycti.get_config_variable(
            "DEP_CREATE_INTRUSION_SETS",
            ["dep", "create_intrusion_sets"],
            config,
            default=True,
        )
        self.create_country_locations = pycti.get_config_variable(
            "DEP_CREATE_COUNTRY_LOCATIONS",
            ["dep", "create_country_locations"],
            config,
            default=True,
        )
        primary_object_value = str(
            pycti.get_config_variable(
                "DEP_PRIMARY_OBJECT",
                ["dep", "primary_object"],
                config,
                default=PrimaryObject.REPORT.value,
            )
        ).strip()
        try:
            self.primary_object = PrimaryObject(primary_object_value.lower())
        except ValueError as exc:
            error = (
                "DEP primary object must be one of: report, incident "
                f"(got: {primary_object_value})"
            )
            raise ValueError(error) from exc

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
        except Exception as e:
            error = "Unable to retrieve IdToken from authentication response"
            raise ValueError(error) from e
        return token

    def _fetch_data(self, start: datetime, end: datetime) -> list[LeakRecord]:
        token = self._authenticate()
        params = {
            "ts": start.strftime("%Y-%m-%d"),
            "te": end.strftime("%Y-%m-%d"),
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

        if isinstance(data, list):
            parsed_items: list[LeakRecord] = []
            for index, raw_item in enumerate(data):
                if not isinstance(raw_item, dict):
                    self.helper.log_warning(
                        "Skipping DEP item at index "
                        f"{index}: expected object, got {type(raw_item).__name__}"
                    )
                    continue
                try:
                    parsed_items.append(LeakRecord(**raw_item))
                except Exception as error:  # pylint: disable=broad-except
                    self.helper.log_warning(
                        "Skipping invalid DEP item for victim "
                        f"{raw_item.get('victim')}: {error}"
                    )
            return parsed_items
        self.helper.log_warning("DEP API returned unexpected payload type")
        return []

    def _create_victim_identity(self, item: LeakRecord) -> stix2.Identity | None:
        victim_name = item.victim
        if not victim_name:
            return None

        external_references: list[dict[str, Any]] = []
        if item.ann_link:
            external_references.append(
                {
                    "source_name": "dep",
                    "url": item.ann_link,
                    "description": item.ann_title,
                }
            )
        if item.site and item.site != item.ann_link:
            external_references.append(
                {
                    "source_name": "victim-site",
                    "url": (
                        f"https://{item.site}"
                        if not item.site.startswith("http")
                        else item.site
                    ),
                }
            )

        description_parts = []
        if item.sector and not self.create_sector_identities:
            description_parts.append(f"Industry sector: {item.sector}")
        if item.revenue:
            description_parts.append(f"Reported revenue: {item.revenue}")
        description = "\n".join(description_parts) or None

        return stix2.Identity(
            id=pycti.Identity.generate_id(victim_name, identity_class="organization"),
            name=victim_name,
            description=description,
            identity_class="organization",
            confidence=self.confidence,
            labels=[self.label_value],
            created_by_ref=self.author_identity,
            external_references=external_references or None,
            object_marking_refs=[TLP_AMBER],
        )

    def _create_sector_identity(self, sector: str) -> stix2.Identity:
        sector_key = sector.lower()
        return stix2.Identity(
            id=pycti.Identity.generate_id(sector_key, identity_class="class"),
            name=sector,
            identity_class="class",
            created_by_ref=self.author_identity,
            confidence=self.confidence,
            labels=[self.label_value],
            object_marking_refs=[TLP_AMBER],
        )

    def _create_intrusion_set(self, actor: str) -> stix2.IntrusionSet:
        actor_key = actor.lower()
        intrusion_set_id = (
            f"intrusion-set--{uuid5(NAMESPACE_URL, f'dep-actor:{actor_key}')}"
        )
        return stix2.IntrusionSet(
            id=intrusion_set_id,
            name=actor,
            confidence=self.confidence,
            labels=[self.label_value],
            created_by_ref=self.author_identity,
            object_marking_refs=[TLP_AMBER],
        )

    def _create_country_location(self, country: str) -> stix2.Location:
        country_key = country.lower()
        location_id = f"location--{uuid5(NAMESPACE_URL, f'dep-country:{country_key}')}"
        return stix2.Location(
            id=location_id,
            name=country,
            country=country,
            confidence=self.confidence,
            labels=[self.label_value],
            created_by_ref=self.author_identity,
            object_marking_refs=[TLP_AMBER],
            custom_properties={"x_opencti_location_type": "Country"},
            allow_custom=True,
        )

    @staticmethod
    def _build_primary_name(item: LeakRecord) -> str:
        victim_name = item.victim or item.victim_domain or "Unknown Victim"
        return f"DEP announcement - {victim_name}"

    @staticmethod
    def _build_primary_description(item: LeakRecord) -> str | None:
        if item.ann_description:
            return unquote(item.ann_description)
        return None

    @staticmethod
    def _build_primary_external_reference(item: LeakRecord) -> dict[str, Any]:
        external_reference: dict[str, Any] = {"source_name": "dep"}
        if item.ann_link:
            external_reference["url"] = item.ann_link
        elif item.site:
            site = item.site
            external_reference["url"] = (
                site if site.startswith("http") else f"https://{site}"
            )
        if item.ann_title:
            external_reference["description"] = item.ann_title
        return external_reference

    @staticmethod
    def _build_primary_custom_properties(item: LeakRecord) -> dict[str, Any]:
        custom_properties: dict[str, Any] = {}
        if item.actor:
            custom_properties["dep_actor"] = item.actor
        if item.country:
            custom_properties["dep_country"] = item.country
        return custom_properties

    def _create_incident(self, item: LeakRecord) -> stix2.Incident:
        incident_name = self._build_primary_name(item)
        description = self._build_primary_description(item)
        first_seen = datetime.combine(item.date, datetime.min.time(), tzinfo=UTC)
        external_reference = self._build_primary_external_reference(item)
        # incident_id must be deterministic to allow updates
        incident_id = f"incident--{uuid5(NAMESPACE_URL, f'dep-announcement:{item.hashid.strip().lower()}')}"
        custom_properties = {
            "incident_type": "cybercrime",
            "first_seen": first_seen,
            **self._build_primary_custom_properties(item),
        }

        return stix2.Incident(
            id=incident_id,
            name=incident_name,
            description=description,
            created=first_seen,
            confidence=self.confidence,
            labels=self._build_labels(item),
            created_by_ref=self.author_identity,
            external_references=[external_reference],
            object_marking_refs=[TLP_AMBER],
            custom_properties=custom_properties,
        )

    def _create_report(self, item: LeakRecord, object_refs: list[str]) -> stix2.Report:
        report_name = self._build_primary_name(item)
        description = self._build_primary_description(item)
        published = datetime.combine(item.date, datetime.min.time(), tzinfo=UTC)
        external_reference = self._build_primary_external_reference(item)
        # report_id must be deterministic to allow updates
        report_id = f"report--{uuid5(NAMESPACE_URL, f'dep-announcement:{item.hashid.strip().lower()}')}"
        custom_properties = self._build_primary_custom_properties(item)

        kwargs: dict[str, Any] = {
            "id": report_id,
            "name": report_name,
            "description": description,
            "published": published,
            "report_types": ["threat-report"],
            "confidence": self.confidence,
            "labels": self._build_labels(item),
            "created_by_ref": self.author_identity,
            "external_references": [external_reference],
            "object_refs": object_refs,
            "object_marking_refs": [TLP_AMBER],
        }
        if custom_properties:
            kwargs["custom_properties"] = custom_properties
        return stix2.Report(**kwargs)

    def _build_labels(self, item: LeakRecord) -> list[str]:
        labels = {self.label_value}
        labels.update(
            f"dep:announcement-type:{announcement_type.value.lower()}"
            for announcement_type in item.announcement_types
        )
        return sorted(labels)

    def _create_site_indicator(self, item: LeakRecord) -> stix2.Indicator | None:
        if not self.enable_site_indicator:
            return None
        domain = item.indicator_domain
        if not domain:
            return None

        pattern = f"[domain-name:value = '{domain}']"
        return stix2.Indicator(
            id=pycti.Indicator.generate_id(pattern),
            name=f"Domain associated with {item.victim or 'unknown victim'}",
            description="Victim domain",
            pattern_type="stix",
            pattern=pattern,
            valid_from=datetime.now(UTC),
            confidence=self.confidence,
            labels=[self.label_value],
            created_by_ref=self.author_identity,
            object_marking_refs=[TLP_AMBER],
        )

    def _create_hash_indicator(self, item: LeakRecord) -> stix2.Indicator | None:
        if not self.enable_hash_indicator:
            return None
        hash_value = item.hashid.strip().lower()
        if not hash_value:
            return None
        hash_type = self._detect_hash_type(hash_value)
        if not hash_type:
            return None

        pattern = f"[file:hashes.'{hash_type}' = '{hash_value}']"
        return stix2.Indicator(
            id=pycti.Indicator.generate_id(pattern),
            name=f"Announcement hash for {item.victim or 'unknown victim'}",
            description="Hash identifier for tracking",
            pattern_type="stix",
            pattern=pattern,
            valid_from=datetime.now(UTC),
            confidence=self.confidence,
            labels=[self.label_value],
            created_by_ref=self.author_identity,
            object_marking_refs=[TLP_AMBER],
        )

    @staticmethod
    def _detect_hash_type(hash_value: str) -> str | None:
        length_to_type = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}
        return length_to_type.get(len(hash_value))

    def _is_low_quality_actor(self, actor: str) -> bool:
        normalized = " ".join(actor.lower().split())
        return normalized in self.GENERIC_ACTOR_VALUES

    def _build_relationship(
        self,
        relationship_type: str,
        source_ref: str,
        target_ref: str,
    ) -> stix2.Relationship:
        return stix2.Relationship(
            id=pycti.StixCoreRelationship.generate_id(
                relationship_type, source_ref, target_ref
            ),
            relationship_type=relationship_type,
            source_ref=source_ref,
            target_ref=target_ref,
            created_by_ref=self.author_identity,
            confidence=self.confidence,
            labels=[self.label_value],
            object_marking_refs=[TLP_AMBER],
        )

    def _send_objects(self, objects: list[stix2._STIXBase21]) -> None:
        if not objects:
            return
        deduped = {obj.id: obj for obj in objects if getattr(obj, "id", None)}
        bundle = stix2.Bundle(objects=list(deduped.values()), allow_custom=True)
        self.helper.send_stix2_bundle(
            bundle.serialize(),
            update=True,
            work_id=self._current_work_id,
            cleanup_inconsistent_bundle=True,
        )

    def _should_skip_item(self, victim: str | None) -> bool:
        if not self.skip_empty_victim:
            return False
        normalized = (victim or "").strip().lower()
        return normalized in {"", "n/a", "none"}

    def _build_indicators(self, item: LeakRecord) -> list[stix2.Indicator]:
        indicators: list[stix2.Indicator] = []
        site_indicator = self._create_site_indicator(item)
        if site_indicator:
            indicators.append(site_indicator)
        hash_indicator = self._create_hash_indicator(item)
        if hash_indicator:
            indicators.append(hash_indicator)
        return indicators

    def _build_indicator_victim_relationships(
        self,
        indicators: list[stix2.Indicator],
        victim: stix2.Identity | None,
    ) -> list[stix2.Relationship]:
        if victim is None:
            return []
        return [
            self._build_relationship("related-to", indicator.id, victim.id)
            for indicator in indicators
        ]

    def _build_cross_entity_relationships(
        self,
        intrusion_set: stix2.IntrusionSet | None,
        sector_identity: stix2.Identity | None,
        country_location: stix2.Location | None,
    ) -> list[stix2._STIXBase21]:
        objects: list[stix2._STIXBase21] = []
        if intrusion_set and sector_identity:
            objects.append(
                self._build_relationship(
                    "targets", intrusion_set.id, sector_identity.id
                )
            )
        if intrusion_set and country_location:
            objects.append(
                self._build_relationship(
                    "targets", intrusion_set.id, country_location.id
                )
            )
        if sector_identity and country_location:
            objects.append(
                self._build_relationship(
                    "related-to", sector_identity.id, country_location.id
                )
            )
        return objects

    def _build_optional_entities(
        self,
        item: LeakRecord,
        victim: stix2.Identity | None,
        incident_id: str | None = None,
    ) -> list[stix2._STIXBase21]:
        objects: list[stix2._STIXBase21] = []
        sector_identity: stix2.Identity | None = None
        if self.create_sector_identities and item.sector and victim:
            sector_identity = self._create_sector_identity(item.sector)
        if sector_identity and victim:
            objects.append(sector_identity)
            objects.append(
                self._build_relationship("part-of", victim.id, sector_identity.id)
            )

        intrusion_set: stix2.IntrusionSet | None = None
        if (
            self.create_intrusion_sets
            and item.actor
            and not self._is_low_quality_actor(item.actor)
        ):
            intrusion_set = self._create_intrusion_set(item.actor)
        if intrusion_set:
            objects.append(intrusion_set)
            if incident_id is not None:
                objects.append(
                    self._build_relationship(
                        "attributed-to", incident_id, intrusion_set.id
                    )
                )

        country_location: stix2.Location | None = None
        if self.create_country_locations and item.country and victim:
            country_location = self._create_country_location(item.country)
        if country_location and victim:
            objects.append(country_location)
            objects.append(
                self._build_relationship("located-at", victim.id, country_location.id)
            )
        objects.extend(
            self._build_cross_entity_relationships(
                intrusion_set, sector_identity, country_location
            )
        )
        return objects

    def _build_content(
        self,
        item: LeakRecord,
        victim: stix2.Identity | None,
        indicators: list[stix2.Indicator],
        incident_id: str | None = None,
    ) -> list[stix2._STIXBase21]:
        content: list[stix2._STIXBase21] = [self.author_identity]
        if victim:
            content.append(victim)
        content.extend(self._build_optional_entities(item, victim, incident_id))
        content.extend(indicators)
        content.extend(self._build_indicator_victim_relationships(indicators, victim))
        return content

    def _process_item(self, item: LeakRecord) -> None:
        if self._should_skip_item(item.victim):
            self.helper.log_info(
                "Skipping DEP item with empty or placeholder victim value"
            )
            return
        victim = self._create_victim_identity(item)
        indicators = self._build_indicators(item)
        if self.primary_object is PrimaryObject.INCIDENT:
            self._process_item_as_incident(item, victim, indicators)
        else:
            self._process_item_as_report(item, victim, indicators)

    def _process_item_as_incident(
        self,
        item: LeakRecord,
        victim: stix2.Identity | None,
        indicators: list[stix2.Indicator],
    ) -> None:
        incident = self._create_incident(item)
        objects = self._build_content(item, victim, indicators, incident.id)
        objects.append(incident)
        if victim:
            objects.append(self._build_relationship("targets", incident.id, victim.id))
        objects.extend(
            self._build_relationship("indicates", indicator.id, incident.id)
            for indicator in indicators
        )
        self._send_objects(objects)

    def _process_item_as_report(
        self,
        item: LeakRecord,
        victim: stix2.Identity | None,
        indicators: list[stix2.Indicator],
    ) -> None:
        content = self._build_content(item, victim, indicators)
        object_refs = [obj.id for obj in content if getattr(obj, "id", None)]
        report = self._create_report(item, object_refs)
        self._send_objects([*content, report])

    def _run_cycle(self) -> None:
        now = datetime.now(UTC)
        start = now - timedelta(days=self.lookback_days)
        state = self.helper.get_state() or {}
        last_run = state.get("last_run")
        if isinstance(last_run, str):
            try:
                start = datetime.fromisoformat(last_run) - timedelta(
                    hours=self.overlap_hours
                )
            except ValueError:
                self.helper.log_warning(
                    f"Ignoring invalid last_run state value: {last_run}"
                )
        elif last_run is not None:
            self.helper.log_warning(
                "Ignoring non-string last_run state value returned by OpenCTI helper"
            )
        end = now

        self.helper.log_info(
            "Fetching DEP data from "
            f"{start.isoformat()} to {end.isoformat()} "
            f"(overlap: {self.overlap_hours}h)"
        )

        self._current_work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id,
            f"DEP connector - {now.strftime('%Y-%m-%d %H:%M:%S')} UTC",
        )
        try:
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
                        f"Failed to process DEP item for victim {item.victim}: {error}"
                    )

            self.helper.log_info("Persisting connector state")
            self.helper.set_state({"last_run": end.isoformat()})
            self.helper.log_info("DEP run completed")
        finally:
            self.helper.api.work.to_processed(
                self._current_work_id,
                f"DEP connector run completed, last_run: {end.isoformat()}",
            )
            self._current_work_id = None

    def run(self) -> None:
        self.helper.log_info("Starting DEP connector")
        self.helper.schedule_iso(
            message_callback=self._run_cycle,
            duration_period=f"PT{self.interval}S",
        )


if __name__ == "__main__":
    DepConnector().run()
