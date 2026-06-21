import pycti  # type: ignore[import-untyped]
import pytest
from pydantic import ValidationError
from stix2 import TLP_AMBER  # type: ignore[import-untyped]
from stix2 import v21 as stix2

from dep_connector import LeakRecord, StixBuilder
from dep_connector.converter_to_stix import AnnouncementType


def build_builder() -> StixBuilder:
    author_identity = stix2.Identity(
        id=pycti.Identity.generate_id("DigIntLab", identity_class="organization"),
        name="DigIntLab",
        identity_class="organization",
        object_marking_refs=[TLP_AMBER],
    )
    return StixBuilder(
        author_identity=author_identity,
        confidence=70,
        label_value="DigIntLab",
    )


def test_leak_record_normalizes_source_fields() -> None:
    item = LeakRecord(
        date="2026-03-27",
        hashid="A" * 64,
        victim="Example Victim",
        annLink="https//example.com/leak",
        site=" Example.com ",
        victimDomain=" Victim.Example.com ",
        sector="  Finance   ",
        actor=" Example Gang ",
        country=" n/a ",
    )

    assert item.ann_link == "https://example.com/leak"
    assert item.site == "Example.com"
    assert item.victim_domain == "Victim.Example.com"
    assert item.sector == "Finance"
    assert item.actor == "Example Gang"
    assert item.country is None
    assert item.normalized_hashid == "a" * 64
    assert item.indicator_domain == "victim.example.com"


def test_indicator_domain_falls_back_to_site() -> None:
    item = LeakRecord(
        date="2026-03-27",
        hashid="b" * 64,
        victim="Example Victim",
        site="https://Portal.Example.com/path",
    )

    assert item.indicator_domain == "portal.example.com"


def test_report_id_is_deterministic_from_hashid() -> None:
    builder = build_builder()
    object_refs = [builder.author_identity.id]
    first = LeakRecord(
        date="2026-03-27",
        hashid="c" * 64,
        victim="Original Victim",
        annLink="https://example.com/original",
        annTitle="Original Title",
        annDescription="Original description",
        dep_dataset="ext",
    )
    second = LeakRecord(
        date="2026-03-27",
        hashid="c" * 64,
        victim="Updated Victim",
        annLink="https://example.com/updated",
        annTitle="Updated Title",
        annDescription="Updated description",
        dep_dataset="dds",
    )

    first_report = builder.create_report(first, object_refs)
    second_report = builder.create_report(second, object_refs)

    assert first_report.id == second_report.id
    assert first_report.name != second_report.name
    assert "dep:dataset:ext" in first_report.labels
    assert "dep:dataset:dds" in second_report.labels


def test_build_primary_description_url_decodes_text() -> None:
    item = LeakRecord(
        date="2026-03-27",
        hashid="e" * 64,
        victim="Encoded Victim",
        annDescription="Leaked%20records%20available",
    )

    assert StixBuilder.build_primary_description(item) == "Leaked records available"


def test_build_primary_external_reference_falls_back_to_site_with_scheme() -> None:
    item = LeakRecord(
        date="2026-03-27",
        hashid="f" * 64,
        victim="Fallback Victim",
        site="portal.example.com",
        annTitle="Fallback title",
    )

    reference = StixBuilder.build_primary_external_reference(item)

    assert reference == {
        "source_name": "dep",
        "url": "https://portal.example.com",
        "description": "Fallback title",
    }


def test_incident_id_is_deterministic_from_hashid() -> None:
    builder = build_builder()
    first = LeakRecord(
        date="2026-03-27",
        hashid="d" * 64,
        victim="Original Victim",
        annLink="https://example.com/original",
    )
    second = LeakRecord(
        date="2026-03-27",
        hashid="d" * 64,
        victim="Updated Victim",
        annLink="https://example.com/updated",
    )

    first_incident = builder.create_incident(first)
    second_incident = builder.create_incident(second)

    assert first_incident.id == second_incident.id
    assert first_incident.name != second_incident.name


def test_leak_record_drops_unknown_announcement_types() -> None:
    item = LeakRecord(
        date="2026-03-27",
        hashid="a" * 64,
        victim="Example Victim",
        annDataTypes=["PII", "CREDENTIALS", "MEDICAL"],
    )

    assert item.announcement_types == [AnnouncementType.PII, AnnouncementType.MEDICAL]


def test_leak_record_coerces_null_announcement_types_to_empty() -> None:
    item = LeakRecord(
        date="2026-03-27",
        hashid="a" * 64,
        victim="Example Victim",
        annDataTypes=None,
    )

    assert item.announcement_types == []


def test_leak_record_rejects_empty_hashid() -> None:
    with pytest.raises(ValidationError):
        LeakRecord(date="2026-03-27", hashid="   ", victim="Example Victim")


def test_victim_external_references_skips_site_matching_ann_link() -> None:
    builder = build_builder()
    item = LeakRecord(
        date="2026-03-27",
        hashid="a" * 64,
        victim="Dedup Victim",
        annLink="https://example.com",
        site="example.com",
    )

    victim = builder.create_victim_identity(item, include_sector_in_description=False)

    assert victim is not None
    assert {ref.source_name for ref in victim.external_references} == {"dep"}


def test_victim_external_references_keeps_distinct_site() -> None:
    builder = build_builder()
    item = LeakRecord(
        date="2026-03-27",
        hashid="b" * 64,
        victim="Distinct Victim",
        annLink="https://example.com/leak",
        site="portal.example.com",
    )

    victim = builder.create_victim_identity(item, include_sector_in_description=False)

    assert victim is not None
    refs = {ref.source_name: ref.url for ref in victim.external_references}
    assert refs == {
        "dep": "https://example.com/leak",
        "victim-site": "https://portal.example.com",
    }


def _full_dep_item() -> dict[str, object]:
    # Mirrors the real DEP API item shape (every observed key) with synthetic,
    # non-sensitive values, so no real breach-victim data is committed.
    return {
        "date": "2026-03-27",
        "hashid": "a" * 64,
        "victim": "Synthetic Corp",
        "sector": "Manufacturing",
        "actor": "Example Gang",
        "country": "Italy",
        "victimCC": "it",
        "naics": "  541611 ",
        "revenue": "$10M-$50M",
        "site": "synthetic.example",
        "annLink": "https://example.com/leak",
        "annTitle": "Synthetic leak",
        "annDescription": "Leaked%20data%20available",
        "victimDomain": "synthetic.example",
        "annDataTypes": ["PII", "FINANCIAL", "FUTURE_TYPE"],
        "amount": "over 45 ye",
        "victimAddress": None,
        "victimCity": "Milan",
        "victimState": "25",
    }


def test_full_real_shaped_item_parses_and_maps() -> None:
    item = LeakRecord(**_full_dep_item(), dep_dataset="ext")

    assert item.victim == "Synthetic Corp"
    assert item.country_code == "IT"
    assert item.naics == "541611"
    assert item.country == "Italy"
    assert item.indicator_domain == "synthetic.example"
    # Unknown enum members dropped; unmapped DEP fields tolerated without crashing.
    assert item.announcement_types == [
        AnnouncementType.PII,
        AnnouncementType.FINANCIAL,
    ]


def test_country_location_uses_alpha2_from_country_code() -> None:
    builder = build_builder()
    item = LeakRecord(
        date="2026-03-27",
        hashid="a" * 64,
        victim="Synthetic Corp",
        country="Italy",
        victimCC="IT",
    )

    location = builder.create_country_location("Italy", item)

    assert location.name == "Italy"
    assert location.country == "IT"


def test_country_location_falls_back_to_name_without_code() -> None:
    builder = build_builder()
    item = LeakRecord(
        date="2026-03-27",
        hashid="a" * 64,
        victim="Synthetic Corp",
        country="Italy",
    )

    location = builder.create_country_location("Italy", item)

    assert location.name == "Italy"
    assert location.country == "Italy"


def test_naics_surfaced_as_custom_property() -> None:
    builder = build_builder()
    item = LeakRecord(
        date="2026-03-27",
        hashid="a" * 64,
        victim="Synthetic Corp",
        country="Italy",
        naics="541611",
    )

    properties = builder.build_primary_custom_properties(item)

    assert properties["dep_naics"] == "541611"
    assert properties["dep_country"] == "Italy"
