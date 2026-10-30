"""Characterization tests: --list-providers and --providers-status for every provider-specific branch.

Snapshots live in tests/snapshots/provider_listing_*.txt.
Regenerate after an intended change with: UPDATE_SNAPSHOTS=1 pytest tests/test_provider_listings.py
"""

import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from url_checker_tools.cli.output_service import OutputService
from url_checker_tools.services.provider_registry import ProviderRegistry

SNAPSHOT_DIR = Path(__file__).parent / "snapshots"
NAMES = [
    "whalebone",
    "virustotal",
    "whois",
    "google_sb",
    "abuseipdb",
    "urlscan",
    "lookyloo",
    "link_analyzer",
    "yara",
    "misp",
]
YARA_LIMITS = {"max_file_size": 10485760, "scan_timeout": 30}


def fake_provider(available, **config):
    class FakeProvider:
        def __init__(self):
            self.config = SimpleNamespace(**config)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def is_available(self):
            return available

    return FakeProvider


def registry(available, configs):
    return ProviderRegistry(
        {name: fake_provider(available, **configs.get(name, {})) for name in NAMES}
    )


SCENARIOS = {
    # Every provider available, with the config attributes each branch reads
    "available": registry(
        True,
        {
            "yara": {
                "rule_paths": ["a.yar", "b.yar", "c.yar", "d.yar"],
                "timeout": 30,
                "max_retries": 3,
                **YARA_LIMITS,
            },
            "whalebone": {"endpoint": "https://wb.test", "min_threat_accuracy": 80},
            "lookyloo": {"endpoint": "https://lookyloo.test"},
            "virustotal": {
                "endpoint": "https://vt.test",
                "rate_limit_per_minute": 4,
            },
            "misp": {"endpoint": "https://misp.test"},
        },
    ),
    # YARA with a rules directory instead of custom rule paths
    "available_rules_dir": registry(
        True, {"yara": {"rules_dir": "data/yara", **YARA_LIMITS}}
    ),
    # Nothing configured
    "unavailable": registry(False, {"yara": {"rules_dir": "data/yara"}}),
}


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_provider_listing_matches_snapshot(scenario, capsys):
    OutputService.list_providers(SCENARIOS[scenario])
    listing = capsys.readouterr().out
    OutputService.provider_status(SCENARIOS[scenario])
    status = capsys.readouterr().out
    actual = "\n".join(["--- list ---", listing, "--- status ---", status])

    snapshot = SNAPSHOT_DIR / f"provider_listing_{scenario}.txt"
    if os.environ.get("UPDATE_SNAPSHOTS") or not snapshot.exists():
        snapshot.write_text(actual, encoding="utf-8")
    assert actual == snapshot.read_text(encoding="utf-8")
