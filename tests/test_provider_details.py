"""Tests for helpers that read provider result details."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from url_checker_tools.services.provider_details import unique_categories


def test_unique_categories_lowercases_and_keeps_first_order():
    details = {"categories": ["Phishing", " phishing ", "Malware", 3, "", "news"]}
    assert unique_categories(details) == ["phishing", "malware", "news"]


def test_unique_categories_falls_back_to_categories_vt():
    assert unique_categories({"categories": [], "categories_vt": ["News"]}) == ["news"]


def test_unique_categories_ignores_missing_or_non_list_values():
    assert unique_categories({}) == []
    assert unique_categories({"categories": "phishing"}) == []
