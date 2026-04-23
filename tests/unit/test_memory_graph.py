from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from shisad.memory.graph import build_knowledge_graph
from shisad.memory.manager import MemoryManager
from shisad.memory.schema import MemoryEntry, MemorySource


def _write_fact(
    manager: MemoryManager,
    *,
    key: str,
    value: str,
    entry_type: str = "fact",
    source_id: str = "graph-test",
) -> MemoryEntry:
    decision = manager.write_with_provenance(
        entry_type=entry_type,
        key=key,
        value=value,
        source=MemorySource(origin="user", source_id=source_id, extraction_method="manual"),
        source_origin="user_direct",
        channel_trust="command",
        confirmation_status="user_asserted",
        source_id=source_id,
        scope="user",
        confidence=0.95,
        confirmation_satisfied=True,
    )
    assert decision.entry is not None
    return decision.entry


def test_m5_knowledge_graph_rebuilds_with_stable_evidence_ids(tmp_path: Path) -> None:
    manager = MemoryManager(tmp_path / "memory")
    shisad = _write_fact(
        manager,
        key="project:shisad",
        value="Shisad depends on MemoryPack for recall and release planning.",
    )
    memory_pack = _write_fact(
        manager,
        key="component:memorypack",
        value="MemoryPack provides recall context for Shisad.",
    )

    graph = build_knowledge_graph(manager.list_entries(limit=10))
    rebuilt = build_knowledge_graph(manager.list_entries(limit=10))

    shisad_id = graph.entity_id_for("Shisad")
    assert shisad_id == rebuilt.entity_id_for("shisad")
    assert shisad_id in graph.nodes
    assert {shisad.id, memory_pack.id} & set(graph.nodes[shisad_id].evidence_entry_ids)

    query = graph.query("Shisad", depth=1, limit=10)
    assert query.root_entity_id == shisad_id
    assert any(edge.relation == "related_to" for edge in query.edges)
    assert all(edge.evidence_entry_ids for edge in query.edges)

    exported = json.loads(graph.export(format="json"))
    assert exported["derived"] is True
    assert any(node["entity_id"] == shisad_id for node in exported["nodes"])
    assert "Evidence" in graph.export(format="md")


def test_m5_knowledge_graph_exports_lifecycle_and_provenance_metadata(
    tmp_path: Path,
) -> None:
    manager = MemoryManager(tmp_path / "memory")
    entry = _write_fact(
        manager,
        key="project:shisad",
        value="Shisad uses MemoryPack for release recall.",
        source_id="graph-metadata",
    )
    entry.valid_from = datetime(2026, 4, 1, tzinfo=UTC)
    entry.valid_to = datetime(2026, 5, 1, tzinfo=UTC)
    entry.decay_score = 0.72
    entry.importance_weight = 1.4
    manager._persist_entry(entry)

    graph = build_knowledge_graph(manager.list_entries(limit=10))
    exported = json.loads(graph.export(format="json"))
    shisad_id = graph.entity_id_for("Shisad")
    node = next(item for item in exported["nodes"] if item["entity_id"] == shisad_id)

    assert node["created_at"] == entry.created_at.isoformat()
    assert node["valid_from"] == entry.valid_from.isoformat()
    assert node["valid_to"] == entry.valid_to.isoformat()
    assert node["decay_score"] == 0.72
    assert node["importance_weight"] == 1.4
    assert node["source_origin"] == "user_direct"
    assert node["trust_band"] == "elevated"
    assert node["source_ids"] == ["graph-metadata"]
    assert node["scopes"] == ["user"]


def test_m5_knowledge_graph_records_hub_and_three_axis_links(tmp_path: Path) -> None:
    manager = MemoryManager(tmp_path / "memory")
    first = _write_fact(
        manager,
        key="project:shisad",
        value="Shisad uses MemoryPack recall for release planning.",
        source_id="graph-axis-1",
    )
    second = _write_fact(
        manager,
        key="component:memorypack",
        value="MemoryPack recall supports Shisad release workflows.",
        source_id="graph-axis-2",
    )
    _write_fact(
        manager,
        key="process:quokka",
        value="QuokkaScheduler retries webhook invoice delivery after transient failures.",
        source_id="graph-axis-3",
    )
    _write_fact(
        manager,
        key="process:webhook",
        value="The retry scheduler handles webhook invoice delivery failures.",
        source_id="graph-axis-4",
    )

    graph = build_knowledge_graph(manager.list_entries(limit=10))

    entry_link = graph.entry_link(first.id, second.id)
    assert entry_link is not None
    assert "entity_cooccurrence" in entry_link.axes
    assert "vector_similarity" in entry_link.axes

    all_axes = {axis for link in graph.entry_links for axis in link.axes}
    assert {"entity_cooccurrence", "tfidf_overlap", "vector_similarity"} <= all_axes
    hubs = graph.hub_nodes(limit=3)
    assert hubs
    assert hubs[0].degree >= 2
