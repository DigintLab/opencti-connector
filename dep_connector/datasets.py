from enum import StrEnum


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
