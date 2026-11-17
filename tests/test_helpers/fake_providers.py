"""Fake providers and MISP reporter shared by the CLI and service tests."""

from datetime import datetime, timezone
from types import SimpleNamespace

from url_checker_tools.core.results import ProviderResult, ThreatLevel

FIXED_TS = datetime(2026, 1, 1, tzinfo=timezone.utc)

SAFE = {"is_threat": False, "threat_level": ThreatLevel.SAFE, "confidence": 0.9}
RESULTS = {
    "whois": {
        **SAFE,
        "details": {
            "domain_name": "example.test",
            "registrar": "Example Registrar",
            "domain_age_days": 9000,
        },
    },
    "link_analyzer": {
        **SAFE,
        "details": {
            "redirect_count": 1,
            "final_url": "https://example.test/login",
            "domain_changed": False,
            "resolved_ips": ["192.0.2.10", "2001:db8::10"],
        },
    },
    "misp": {**SAFE, "details": {"events_found": 0}},
    "whalebone": {
        **SAFE,
        "details": {"threat_types": [], "categories": ["news"], "max_accuracy": 0},
    },
    "virustotal": {
        "is_threat": True,
        "threat_level": ThreatLevel.MALICIOUS,
        "confidence": 0.8,
        "details": {
            "malicious_count": 5,
            "total_engines": 90,
            "categories": ["phishing", "Phishing"],
        },
    },
    "yara": {
        **SAFE,
        "details": {"scan_summary": "No pattern matches", "matches": []},
    },
}


def fake_provider(name, available=True, error=None):
    """Duck-typed stand-in for a provider class (constructed with no args)."""

    class FakeProvider:
        def __init__(self):
            self.config = SimpleNamespace(verbose=False)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def is_available(self):
            return available

        def scan_with_timing(self, target):
            if error:
                raise RuntimeError(error)
            return ProviderResult(
                provider=name,
                target=target,
                timestamp=FIXED_TS,
                execution_time=0.5,
                **RESULTS[name],
            )

    return FakeProvider


FAKE_PROVIDERS = {
    **{name: fake_provider(name) for name in RESULTS},
    "google_sb": fake_provider("google_sb", available=False),
    "abuseipdb": fake_provider("abuseipdb", error="connection refused"),
}


class FakeMISPReporter:
    def __init__(self, verbose=False):
        pass

    def is_available(self):
        return True

    def create_event(self, target, results, session_id):
        return {"event_id": "42", "uuid": "00000000-0000-0000-0000-000000000042"}
