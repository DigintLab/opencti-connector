from datetime import date as dt_date
from enum import StrEnum
from urllib.parse import urlsplit

from pydantic import ConfigDict, Field, field_validator
from pydantic.dataclasses import dataclass


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
    def normalized_hashid(self) -> str:
        return self.hashid.strip().lower()

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
