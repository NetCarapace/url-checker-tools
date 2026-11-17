"""
URLChecker-Tools - Clean threat intelligence tool with modern architecture.

A streamlined tool for checking URLs and domains against multiple
threat intelligence sources.
"""

# Import core components of new architecture
from url_checker_tools.core.results import ProviderResult, ThreatLevel
from url_checker_tools.output.formatters import get_formatter

__version__ = "1.0.0"
__authors__ = "see CONTRIBUTORS.md"

__all__ = [
    "ProviderResult",
    "ThreatLevel",
    "get_formatter",
]
