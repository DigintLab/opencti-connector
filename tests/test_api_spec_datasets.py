import json
import re
from pathlib import Path

from dep_connector import DepDataset


def test_dep_dataset_enum_matches_api_spec() -> None:
    spec_path = Path(__file__).resolve().parent.parent / "dep-api-spec.json"
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    parameters = spec["paths"]["/dbtr/privlist"]["get"]["parameters"]
    description = next(
        parameter["description"]
        for parameter in parameters
        if parameter["name"] == "dset"
    )
    dataset_values = set(re.findall(r"“([a-z]{3})”", description))

    assert dataset_values == set(DepDataset)
