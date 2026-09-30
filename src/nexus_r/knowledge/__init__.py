"""Knowledge engine: CWE / ATT&CK / reference enrichment."""

from nexus_r.knowledge.enrich import enrich_report
from nexus_r.knowledge.mappings import KNOWLEDGE, KnowledgeEntry

__all__ = ["KNOWLEDGE", "KnowledgeEntry", "enrich_report"]
