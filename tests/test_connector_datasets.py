import pytest

from dep_connector import DepConnector, DepDataset


@pytest.mark.parametrize(
    ("raw_datasets", "expected"),
    [
        ("ext,dds", (DepDataset.EXTORTION, DepDataset.DDOS)),
        ("extortion,ddos", (DepDataset.EXTORTION, DepDataset.DDOS)),
        (
            "ext,ddos,vandalism",
            (DepDataset.EXTORTION, DepDataset.DDOS, DepDataset.VANDALISM),
        ),
        (["ext", "dds"], (DepDataset.EXTORTION, DepDataset.DDOS)),
        (["extortion", "ddos"], (DepDataset.EXTORTION, DepDataset.DDOS)),
        (
            [" ext ", "ddos", "extortion"],
            (DepDataset.EXTORTION, DepDataset.DDOS),
        ),
    ],
)
def test_parse_datasets_accepts_multiple_official_values(
    raw_datasets: object,
    expected: tuple[DepDataset, ...],
) -> None:
    connector = DepConnector.__new__(DepConnector)

    assert connector._parse_datasets(raw_datasets) == expected


def test_parse_datasets_rejects_unknown_values() -> None:
    connector = DepConnector.__new__(DepConnector)

    with pytest.raises(ValueError, match="supported values or aliases"):
        connector._parse_datasets("ext,sanctions")


def test_parse_datasets_requires_at_least_one_value() -> None:
    connector = DepConnector.__new__(DepConnector)

    with pytest.raises(ValueError, match="at least one dataset"):
        connector._parse_datasets("")
