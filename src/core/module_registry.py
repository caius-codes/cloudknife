"""
CloudKnife Module Registry - Auto-discovery and search engine.

Automatically discovers modules via introspection of category __init__.py imports.
Provides search functionality across module names, docstrings, and categories.
"""

import importlib
import inspect
from dataclasses import dataclass
from typing import List, Optional


@dataclass(frozen=True)
class ModuleInfo:
    """Immutable module metadata container."""

    name: str
    cloud: str
    category: str
    docstring: str
    full_docstring: str


class ModuleRegistry:
    """Module discovery and search registry for CloudKnife."""

    def __init__(self, modules: List[ModuleInfo]) -> None:
        """
        Initialize registry with discovered modules.

        Args:
            modules: List of discovered module metadata
        """
        self._modules = modules

    @property
    def modules(self) -> List[ModuleInfo]:
        """Get all registered modules."""
        return self._modules

    @staticmethod
    def discover(cloud: str) -> "ModuleRegistry":
        """
        Auto-discover modules for a cloud provider via introspection.

        Scans category packages (enumeration, lateral_movement, etc.) and extracts
        metadata from __all__ lists and function docstrings.

        Args:
            cloud: Cloud provider name ("aws", "gcp", "azure")

        Returns:
            ModuleRegistry instance with discovered modules

        Raises:
            ValueError: If cloud provider is not supported
        """
        categories_map = {
            "aws": ["enumeration", "exfiltration", "lateral", "exploitation", "persistence"],
            "gcp": ["enumeration", "exfiltration", "lateral_movement"],
            "azure": ["enumeration", "exfiltration", "exploitation", "miscellaneous"],
        }

        if cloud not in categories_map:
            raise ValueError(f"Unsupported cloud: {cloud}. Must be aws, gcp, or azure")

        modules = []
        categories = categories_map[cloud]

        for category in categories:
            try:
                pkg = importlib.import_module(f"src.clouds.{cloud}.modules.{category}")
            except ImportError as e:
                continue

            all_exports = getattr(pkg, "__all__", [])

            for func_name in all_exports:
                try:
                    func = getattr(pkg, func_name)
                    doc = inspect.getdoc(func) or ""
                    summary = _extract_docstring_summary(doc)

                    modules.append(
                        ModuleInfo(
                            name=func_name,
                            cloud=cloud,
                            category=category,
                            docstring=summary,
                            full_docstring=doc,
                        )
                    )
                except (AttributeError, TypeError):
                    continue

        return ModuleRegistry(modules)

    def search(self, query: str) -> List[ModuleInfo]:
        """
        Search modules by keyword with three-tier ranking.

        Tier 1 (highest): Module name contains query
        Tier 2 (medium): Docstring contains query
        Tier 3 (lowest): Category contains query

        Args:
            query: Search keyword (case-insensitive)

        Returns:
            List of matching modules, sorted by relevance tier then alphabetically
        """
        if not query:
            return []

        query_lower = query.lower()
        results_by_tier = {1: [], 2: [], 3: []}

        for mod in self._modules:
            if query_lower in mod.name.lower():
                results_by_tier[1].append(mod)
            elif query_lower in mod.docstring.lower():
                results_by_tier[2].append(mod)
            elif query_lower in mod.category.lower():
                results_by_tier[3].append(mod)

        combined = []
        for tier in [1, 2, 3]:
            sorted_tier = sorted(results_by_tier[tier], key=lambda m: m.name)
            combined.extend(sorted_tier)

        return combined


def _extract_docstring_summary(docstring: str) -> str:
    """
    Extract first line of docstring as summary.

    Args:
        docstring: Full docstring text

    Returns:
        First non-empty line, stripped of whitespace
    """
    if not docstring:
        return ""

    lines = docstring.strip().split("\n")
    for line in lines:
        stripped = line.strip()
        if stripped:
            return stripped

    return ""
