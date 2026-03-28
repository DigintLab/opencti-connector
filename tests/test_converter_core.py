import pycti  # type: ignore[import-untyped]
from stix2 import TLP_AMBER  # type: ignore[import-untyped]
from stix2 import v21 as stix2

from dep_connector import LeakRecord, StixBuilder


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
