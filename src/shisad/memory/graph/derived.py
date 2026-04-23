"""Rebuildable knowledge graph derived from canonical memory entries."""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from itertools import combinations
from typing import Any

from shisad.memory.schema import MemoryEntry

_STOPWORDS = {
    "a",
    "after",
    "and",
    "as",
    "at",
    "by",
    "for",
    "from",
    "i",
    "in",
    "is",
    "it",
    "my",
    "on",
    "or",
    "the",
    "this",
    "to",
    "uses",
    "with",
}
_TOKEN_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9_:-]{1,80}")
_CAMEL_OR_CAP_RE = re.compile(r"\b[A-Z][A-Za-z0-9_:-]{2,}\b")


@dataclass
class GraphNode:
    entity_id: str
    name: str
    node_type: str = "concept"
    evidence_entry_ids: list[str] = field(default_factory=list)
    decay_score: float = 1.0
    importance_weight: float = 1.0
    source_origin: str = ""
    trust_band: str = "untrusted"
    degree: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "name": self.name,
            "node_type": self.node_type,
            "evidence_entry_ids": list(self.evidence_entry_ids),
            "decay_score": self.decay_score,
            "importance_weight": self.importance_weight,
            "source_origin": self.source_origin,
            "trust_band": self.trust_band,
            "degree": self.degree,
        }


@dataclass
class GraphEdge:
    edge_id: str
    source_id: str
    target_id: str
    relation: str = "related_to"
    evidence_entry_ids: list[str] = field(default_factory=list)
    axes: list[str] = field(default_factory=list)
    confidence: float = 0.0
    decay_score: float = 1.0
    importance_weight: float = 1.0
    source_origin: str = ""
    trust_band: str = "untrusted"

    def to_dict(self) -> dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "relation": self.relation,
            "evidence_entry_ids": list(self.evidence_entry_ids),
            "axes": list(self.axes),
            "confidence": self.confidence,
            "decay_score": self.decay_score,
            "importance_weight": self.importance_weight,
            "source_origin": self.source_origin,
            "trust_band": self.trust_band,
        }


@dataclass
class MemoryEntryLink:
    entry_id: str
    other_entry_id: str
    axes: list[str]
    score: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "entry_id": self.entry_id,
            "other_entry_id": self.other_entry_id,
            "axes": list(self.axes),
            "score": self.score,
        }


@dataclass
class GraphQueryResult:
    root_entity_id: str
    nodes: list[GraphNode]
    edges: list[GraphEdge]


def _normalize_entity(value: str) -> str:
    tokens = _TOKEN_RE.findall(value.lower())
    return " ".join(tokens).strip()


def _stable_id(prefix: str, value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]
    return f"{prefix}_{digest}"


def _tokens(value: Any) -> set[str]:
    text = json.dumps(value, sort_keys=True) if isinstance(value, (dict, list)) else str(value)
    return {
        token.lower()
        for token in _TOKEN_RE.findall(text)
        if token.lower() not in _STOPWORDS and len(token) > 2
    }


def _entry_text(entry: MemoryEntry) -> str:
    value = (
        json.dumps(entry.value, sort_keys=True)
        if isinstance(entry.value, (dict, list))
        else str(entry.value)
    )
    return f"{entry.key}\n{entry.predicate or ''}\n{value}"


def _infer_node_type(entry: MemoryEntry, entity_name: str) -> str:
    key_head = entry.key.split(":", 1)[0].strip().lower()
    if key_head in {"person", "org", "project", "component", "issue", "process", "meeting"}:
        return key_head
    if str(entry.entry_type) in {"decision", "todo"}:
        return str(entry.entry_type)
    normalized = entity_name.lower()
    if any(marker in normalized for marker in ("inc", "corp", "acme")):
        return "org"
    return "concept"


def _extract_entities(entry: MemoryEntry) -> list[str]:
    text = _entry_text(entry)
    candidates: list[str] = []
    if ":" in entry.key:
        candidates.append(entry.key.split(":", 1)[1])
    candidates.extend(_CAMEL_OR_CAP_RE.findall(text))
    for token in _tokens(text):
        if token.endswith(("pack", "scheduler")) or "-" in token or ":" in token:
            candidates.append(token)
    seen: set[str] = set()
    entities: list[str] = []
    for candidate in candidates:
        normalized = _normalize_entity(candidate)
        if not normalized or normalized in _STOPWORDS or normalized in seen:
            continue
        seen.add(normalized)
        entities.append(candidate.strip())
    return entities


def _cosine(left: set[str], right: set[str]) -> float:
    if not left or not right:
        return 0.0
    overlap = len(left & right)
    return overlap / math.sqrt(len(left) * len(right))


class DerivedKnowledgeGraph:
    """In-memory derived graph that can be rebuilt from memory entries."""

    def __init__(
        self,
        *,
        nodes: dict[str, GraphNode],
        edges: dict[str, GraphEdge],
        entry_links: list[MemoryEntryLink],
    ) -> None:
        self.nodes = nodes
        self.edges = edges
        self.entry_links = entry_links

    @classmethod
    def from_entries(cls, entries: Iterable[MemoryEntry]) -> DerivedKnowledgeGraph:
        entry_list = [entry for entry in entries if entry.status == "active"]
        nodes: dict[str, GraphNode] = {}
        edges: dict[str, GraphEdge] = {}
        entry_entities: dict[str, set[str]] = {}
        entry_tokens: dict[str, set[str]] = {}
        token_document_counts: Counter[str] = Counter()

        for entry in entry_list:
            entities = _extract_entities(entry)
            entity_ids: set[str] = set()
            for name in entities:
                entity_id = cls.entity_id_for(name)
                entity_ids.add(entity_id)
                node = nodes.get(entity_id)
                if node is None:
                    node = GraphNode(
                        entity_id=entity_id,
                        name=name.strip(),
                        node_type=_infer_node_type(entry, name),
                        source_origin=entry.source_origin,
                        trust_band=entry.trust_band,
                    )
                    nodes[entity_id] = node
                if entry.id not in node.evidence_entry_ids:
                    node.evidence_entry_ids.append(entry.id)
                node.decay_score = min(node.decay_score, entry.decay_score)
                node.importance_weight = max(node.importance_weight, entry.importance_weight)
            entry_entities[entry.id] = entity_ids
            tokens = _tokens(_entry_text(entry))
            entry_tokens[entry.id] = tokens
            token_document_counts.update(tokens)

            for left_id, right_id in combinations(sorted(entity_ids), 2):
                edge_id = cls.edge_id_for(left_id, right_id, "related_to")
                edge = edges.get(edge_id)
                if edge is None:
                    edge = GraphEdge(
                        edge_id=edge_id,
                        source_id=left_id,
                        target_id=right_id,
                        axes=["entity_cooccurrence"],
                        source_origin=entry.source_origin,
                        trust_band=entry.trust_band,
                    )
                    edges[edge_id] = edge
                if entry.id not in edge.evidence_entry_ids:
                    edge.evidence_entry_ids.append(entry.id)
                edge.confidence = min(0.99, max(edge.confidence, entry.confidence))
                edge.decay_score = min(edge.decay_score, entry.decay_score)
                edge.importance_weight = max(edge.importance_weight, entry.importance_weight)

        entry_links = cls._build_entry_links(
            entry_list,
            entry_entities=entry_entities,
            entry_tokens=entry_tokens,
            token_document_counts=token_document_counts,
        )
        for edge in edges.values():
            nodes[edge.source_id].degree += 1
            nodes[edge.target_id].degree += 1
        return cls(nodes=nodes, edges=edges, entry_links=entry_links)

    @staticmethod
    def entity_id_for(name: str) -> str:
        normalized = _normalize_entity(name)
        return _stable_id("ent", normalized or "unknown")

    @staticmethod
    def edge_id_for(source_id: str, target_id: str, relation: str) -> str:
        left, right = sorted((source_id, target_id))
        return _stable_id("edge", f"{left}:{relation}:{right}")

    def entry_link(self, entry_id: str, other_entry_id: str) -> MemoryEntryLink | None:
        wanted = {entry_id, other_entry_id}
        for link in self.entry_links:
            if {link.entry_id, link.other_entry_id} == wanted:
                return link
        return None

    def query(self, entity: str, *, depth: int = 1, limit: int = 10) -> GraphQueryResult:
        root_id = entity if entity in self.nodes else self.entity_id_for(entity)
        if root_id not in self.nodes:
            return GraphQueryResult(root_entity_id=root_id, nodes=[], edges=[])
        node_ids = {root_id}
        selected_edges: list[GraphEdge] = []
        frontier = {root_id}
        for _ in range(max(1, depth)):
            next_frontier: set[str] = set()
            for edge in self.edges.values():
                if edge.source_id not in frontier and edge.target_id not in frontier:
                    continue
                selected_edges.append(edge)
                other = edge.target_id if edge.source_id in frontier else edge.source_id
                if other not in node_ids:
                    next_frontier.add(other)
                    node_ids.add(other)
            frontier = next_frontier
            if not frontier:
                break
        nodes = [self.nodes[node_id] for node_id in node_ids if node_id in self.nodes]
        nodes.sort(key=lambda node: (node.entity_id != root_id, -node.degree, node.name.lower()))
        unique_edges = {edge.edge_id: edge for edge in selected_edges}
        edges = sorted(unique_edges.values(), key=lambda edge: (-edge.confidence, edge.edge_id))
        return GraphQueryResult(root_entity_id=root_id, nodes=nodes[:limit], edges=edges[:limit])

    def hub_nodes(self, *, limit: int = 10) -> list[GraphNode]:
        ranked = sorted(
            self.nodes.values(),
            key=lambda node: (node.degree, len(node.evidence_entry_ids), node.name.lower()),
            reverse=True,
        )
        return ranked[:limit]

    def export(self, *, format: str = "json") -> str:
        if format == "json":
            return json.dumps(
                {
                    "derived": True,
                    "nodes": [node.to_dict() for node in self.nodes.values()],
                    "edges": [edge.to_dict() for edge in self.edges.values()],
                    "entry_links": [link.to_dict() for link in self.entry_links],
                },
                indent=2,
                sort_keys=True,
            )
        if format == "md":
            lines = ["# Derived Knowledge Graph", "", "## Nodes"]
            for node in sorted(self.nodes.values(), key=lambda item: item.name.lower()):
                evidence = ", ".join(node.evidence_entry_ids)
                lines.append(f"- **{node.name}** (`{node.entity_id}`) - Evidence: {evidence}")
            lines.extend(["", "## Edges"])
            for edge in sorted(self.edges.values(), key=lambda item: item.edge_id):
                source = self.nodes.get(edge.source_id)
                target = self.nodes.get(edge.target_id)
                source_name = source.name if source is not None else edge.source_id
                target_name = target.name if target is not None else edge.target_id
                evidence = ", ".join(edge.evidence_entry_ids)
                axes = ", ".join(edge.axes)
                lines.append(
                    f"- {source_name} -> {target_name} "
                    f"({edge.relation}; {axes}) Evidence: {evidence}"
                )
            return "\n".join(lines)
        raise ValueError(f"Unsupported graph export format: {format}")

    @staticmethod
    def _build_entry_links(
        entries: list[MemoryEntry],
        *,
        entry_entities: dict[str, set[str]],
        entry_tokens: dict[str, set[str]],
        token_document_counts: Counter[str],
    ) -> list[MemoryEntryLink]:
        links: list[MemoryEntryLink] = []
        total_docs = max(1, len(entries))
        for left, right in combinations(entries, 2):
            axes: list[str] = []
            if entry_entities.get(left.id, set()) & entry_entities.get(right.id, set()):
                axes.append("entity_cooccurrence")
            cosine = _cosine(entry_tokens.get(left.id, set()), entry_tokens.get(right.id, set()))
            if cosine >= 0.32:
                axes.append("vector_similarity")
            shared_tokens = entry_tokens.get(left.id, set()) & entry_tokens.get(right.id, set())
            rare_overlap = {
                token
                for token in shared_tokens
                if token_document_counts[token] <= max(2, math.ceil(total_docs / 2))
            }
            if rare_overlap:
                axes.append("tfidf_overlap")
            if not axes:
                continue
            score = min(1.0, (0.34 * len(axes)) + (0.33 * cosine))
            links.append(
                MemoryEntryLink(
                    entry_id=left.id,
                    other_entry_id=right.id,
                    axes=axes,
                    score=round(score, 4),
                )
            )
        links.sort(key=lambda link: (link.entry_id, link.other_entry_id))
        return links


def build_knowledge_graph(entries: Iterable[MemoryEntry]) -> DerivedKnowledgeGraph:
    return DerivedKnowledgeGraph.from_entries(entries)
