"""Tests for provider discovery and selection."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from url_checker_tools.config.robot_config import ProviderConfig, RobotModeConfig
from url_checker_tools.services.provider_registry import (
    DEFAULT_PROVIDERS,
    ProviderRegistry,
)


def fake_provider(available, checks):
    """Provider class whose availability checks are counted in `checks`."""

    class FakeProvider:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def is_available(self):
            checks.append(1)
            return available

    return FakeProvider


def test_default_registry_has_all_providers():
    registry = ProviderRegistry()
    assert list(registry.providers) == list(DEFAULT_PROVIDERS)
    assert registry.get("virustotal") is DEFAULT_PROVIDERS["virustotal"]
    assert registry.get("unknown") is None


def test_select_baseline_by_default():
    assert ProviderRegistry().select(None, False, False) == list(
        ProviderConfig.get_baseline_providers()
    )


def test_select_providers_adds_to_baseline_without_duplicates():
    baseline = list(ProviderConfig.get_baseline_providers())
    selected = ProviderRegistry().select(f"virustotal, {baseline[0]}", False, False)
    assert selected == baseline + ["virustotal"]


def test_select_robot_set():
    assert ProviderRegistry().select(None, False, True) == list(
        RobotModeConfig.get_robot_providers()
    )


def test_select_all_returns_available_providers_in_registry_order():
    checks = []
    registry = ProviderRegistry(
        {
            "a": fake_provider(True, checks),
            "b": fake_provider(False, checks),
            "c": fake_provider(True, checks),
        }
    )
    assert registry.select(None, True, False) == ["a", "c"]


def test_availability_is_cached_until_refresh():
    checks = []
    registry = ProviderRegistry({"a": fake_provider(True, checks)})

    assert registry.available() == ["a"]
    assert registry.available() == ["a"]
    assert len(checks) == 1

    registry.available(force_refresh=True)
    assert len(checks) == 2
