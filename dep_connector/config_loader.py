import os
from pathlib import Path
from typing import Any

import yaml

_PROJECT_ROOT = Path(__file__).resolve().parent.parent


def load_config() -> dict[str, Any]:
    config_path = os.environ.get(
        "OPENCTI_CONFIG_FILE",
        _PROJECT_ROOT / "config.yml",
    )
    config_path = Path(config_path)
    if config_path.exists():
        with config_path.open(encoding="utf-8") as config_file:
            return yaml.safe_load(config_file) or {}
    return {}
