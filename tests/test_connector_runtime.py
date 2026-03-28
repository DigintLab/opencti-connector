from datetime import UTC, datetime
from unittest.mock import Mock, patch

import pycti  # type: ignore[import-untyped]
from stix2 import TLP_AMBER  # type: ignore[import-untyped]
from stix2 import v21 as stix2

from dep_connector import DepConnector, DepDataset, PrimaryObject


def test_should_skip_item_honors_flag() -> None:
    connector = DepConnector.__new__(DepConnector)
    connector.skip_empty_victim = True

    assert connector._should_skip_item("")
    assert connector._should_skip_item("n/a")
    assert connector._should_skip_item(" none ")
    assert not connector._should_skip_item("Acme Corp")

    connector.skip_empty_victim = False
    assert not connector._should_skip_item("")


def test_fetch_data_fetches_one_dataset_with_injected_dep_dataset() -> None:
    connector = DepConnector.__new__(DepConnector)
    connector.helper = Mock()
    connector.client = Mock()
    connector.client.fetch_raw.return_value = [
        {"date": "2026-03-27", "hashid": "a" * 64, "victim": "Ext Victim"}
    ]

    items = connector._fetch_data(
        DepDataset.EXTORTION,
        datetime(2026, 3, 26, tzinfo=UTC),
        datetime(2026, 3, 27, tzinfo=UTC),
        "token-123",
    )

    assert [item.dep_dataset for item in items] == ["ext"]
    assert [item.victim for item in items] == ["Ext Victim"]
    connector.client.fetch_raw.assert_called_once_with(
        dataset=DepDataset.EXTORTION,
        start_date="2026-03-26",
        end_date="2026-03-27",
        token="token-123",
    )
    connector.helper.log_info.assert_called_once_with("Fetching DEP dataset 'ext'")


def test_fetch_data_skips_invalid_records_without_aborting() -> None:
    connector = DepConnector.__new__(DepConnector)
    connector.helper = Mock()
    connector.client = Mock()
    connector.client.fetch_raw.return_value = [
        {"date": "2026-03-27", "hashid": "a" * 64, "victim": "Valid Victim"},
        {"date": "2026-03-27", "victim": "Missing Hash"},
    ]

    items = connector._fetch_data(
        DepDataset.EXTORTION,
        datetime(2026, 3, 26, tzinfo=UTC),
        datetime(2026, 3, 27, tzinfo=UTC),
        "token-123",
    )

    assert len(items) == 1
    assert items[0].victim == "Valid Victim"
    connector.helper.log_warning.assert_called_once()


def test_build_indicators_collects_enabled_non_empty_indicators() -> None:
    connector = DepConnector.__new__(DepConnector)
    connector.enable_site_indicator = True
    connector.enable_hash_indicator = True
    connector.stix = Mock()

    site_indicator = Mock()
    hash_indicator = Mock()
    connector.stix.create_site_indicator.return_value = site_indicator
    connector.stix.create_hash_indicator.return_value = hash_indicator
    item = Mock()

    assert connector._build_indicators(item) == [site_indicator, hash_indicator]


def test_process_item_skips_placeholder_victim_before_building_content() -> None:
    connector = DepConnector.__new__(DepConnector)
    connector.skip_empty_victim = True
    connector.helper = Mock()
    connector.stix = Mock()
    connector.enable_site_indicator = False
    connector.enable_hash_indicator = False
    connector.primary_object = PrimaryObject.REPORT

    item = Mock(victim=" n/a ")

    connector._process_item(item)

    connector.helper.log_info.assert_called_once_with(
        "Skipping DEP item with empty or placeholder victim value"
    )
    connector.stix.create_victim_identity.assert_not_called()


def test_process_item_routes_to_report_mode() -> None:
    connector = DepConnector.__new__(DepConnector)
    connector.skip_empty_victim = False
    connector.create_sector_identities = False
    connector.helper = Mock()
    connector.stix = Mock()
    connector.enable_site_indicator = False
    connector.enable_hash_indicator = False
    connector.primary_object = PrimaryObject.REPORT

    victim = Mock()
    connector.stix.create_victim_identity.return_value = victim
    item = Mock(victim="Acme Corp")

    with (
        patch.object(
            connector, "_build_indicators", return_value=[]
        ) as build_indicators,
        patch.object(connector, "_process_item_as_report") as process_as_report,
        patch.object(connector, "_process_item_as_incident") as process_as_incident,
    ):
        connector._process_item(item)

    connector.stix.create_victim_identity.assert_called_once_with(
        item,
        include_sector_in_description=True,
    )
    build_indicators.assert_called_once_with(item)
    process_as_report.assert_called_once_with(item, victim, [])
    process_as_incident.assert_not_called()


def test_send_objects_deduplicates_by_stix_id_before_sending() -> None:
    connector = DepConnector.__new__(DepConnector)
    connector.helper = Mock()
    connector._current_work_id = "work-id"

    first = stix2.Identity(
        id=pycti.Identity.generate_id("Example Victim", identity_class="organization"),
        name="Example Victim",
        identity_class="organization",
        object_marking_refs=[TLP_AMBER],
    )
    duplicate = stix2.Identity(
        id=first.id,
        name="Example Victim Duplicate",
        identity_class="organization",
        object_marking_refs=[TLP_AMBER],
    )
    second = stix2.Identity(
        id=pycti.Identity.generate_id("Second Victim", identity_class="organization"),
        name="Second Victim",
        identity_class="organization",
        object_marking_refs=[TLP_AMBER],
    )

    connector._send_objects([first, duplicate, second])

    connector.helper.send_stix2_bundle.assert_called_once()
    sent_bundle = connector.helper.send_stix2_bundle.call_args.args[0]
    assert sent_bundle.count(first.id) == 1
    assert sent_bundle.count(second.id) == 1


def test_resolve_run_window_start_uses_dataset_specific_state() -> None:
    connector = DepConnector.__new__(DepConnector)
    connector.lookback_days = 7
    connector.overlap_hours = 24
    connector.helper = Mock()
    now = datetime(2026, 3, 28, tzinfo=UTC)
    state = {"last_run_by_dataset": {"dds": "2026-03-27T09:00:00+00:00"}}

    start = connector._resolve_dataset_window_start(DepDataset.DDOS, now, state)

    assert start == datetime(2026, 3, 26, 9, 0, tzinfo=UTC)


def test_resolve_run_window_start_new_dataset_uses_lookback_when_map_exists() -> None:
    connector = DepConnector.__new__(DepConnector)
    connector.lookback_days = 7
    connector.overlap_hours = 24
    connector.helper = Mock()
    now = datetime(2026, 3, 28, tzinfo=UTC)
    state = {"last_run_by_dataset": {"ext": "2026-03-27T09:00:00+00:00"}}

    start = connector._resolve_dataset_window_start(DepDataset.DDOS, now, state)

    assert start == datetime(2026, 3, 21, tzinfo=UTC)


def test_resolve_run_window_start_without_dataset_state_uses_lookback() -> None:
    connector = DepConnector.__new__(DepConnector)
    connector.lookback_days = 7
    connector.overlap_hours = 24
    connector.helper = Mock()
    now = datetime(2026, 3, 28, tzinfo=UTC)

    start = connector._resolve_dataset_window_start(DepDataset.EXTORTION, now, {})

    assert start == datetime(2026, 3, 21, tzinfo=UTC)


def test_persist_dataset_state_merges_existing_dataset_entries() -> None:
    connector = DepConnector.__new__(DepConnector)
    connector.helper = Mock()
    connector.helper.get_state.return_value = {
        "last_run_by_dataset": {"ext": "2026-03-27T09:00:00+00:00"}
    }
    end = datetime(2026, 3, 28, 12, 0, tzinfo=UTC)

    connector._persist_dataset_state(DepDataset.DDOS, end)

    connector.helper.set_state.assert_called_once_with(
        {
            "last_run_by_dataset": {
                "ext": "2026-03-27T09:00:00+00:00",
                "dds": "2026-03-28T12:00:00+00:00",
            }
        }
    )
