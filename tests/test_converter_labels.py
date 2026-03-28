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


def build_item() -> LeakRecord:
    return LeakRecord(
        date="2026-03-27",
        hashid="a" * 64,
        victim="Example Victim",
        sector="Finance",
        actor="Example Gang",
        country="Italy",
        site="example.com",
        annDataTypes=["PII"],
        dep_dataset="dds",
    )


def test_build_labels_include_dataset_and_announcement_type() -> None:
    builder = build_builder()
    item = build_item()

    assert builder.build_labels(item) == [
        "DigIntLab",
        "dep:announcement-type:pii",
        "dep:dataset:dds",
    ]


def test_dep_objects_and_relationships_propagate_labels() -> None:
    builder = build_builder()
    item = build_item()

    victim = builder.create_victim_identity(item, include_sector_in_description=False)
    assert victim is not None
    sector = builder.create_sector_identity("Finance", item)
    intrusion_set = builder.create_intrusion_set("Example Gang", item)
    country = builder.create_country_location("Italy", item)
    site_indicator = builder.create_site_indicator(item)
    hash_indicator = builder.create_hash_indicator(item)
    relationship = builder.build_relationship(
        item, "targets", intrusion_set.id, victim.id
    )

    expected_labels = [
        "DigIntLab",
        "dep:announcement-type:pii",
        "dep:dataset:dds",
    ]
    assert victim.labels == expected_labels
    assert sector.labels == expected_labels
    assert intrusion_set.labels == expected_labels
    assert country.labels == expected_labels
    assert site_indicator is not None
    assert site_indicator.labels == expected_labels
    assert hash_indicator is not None
    assert hash_indicator.labels == expected_labels
    assert relationship.labels == expected_labels
