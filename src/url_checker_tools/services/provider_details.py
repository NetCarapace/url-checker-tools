"""Helpers that read provider-specific fields from ProviderResult.details."""

from typing import Any, Dict, List


def unique_categories(details: Dict[str, Any]) -> List[str]:
    """VirusTotal categories, lowercased and de-duplicated, in their original order."""
    cats = details.get("categories") or details.get("categories_vt") or []
    if not isinstance(cats, list):
        return []
    seen = set()
    unique = []
    for c in cats:
        if isinstance(c, str):
            cn = c.strip().lower()
            if cn and cn not in seen:
                seen.add(cn)
                unique.append(cn)
    return unique
