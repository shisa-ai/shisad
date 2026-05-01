from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from shisad.daemon.handlers._impl_memory import MemoryImplMixin
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
    supersedes: str | None = None,
    source_origin: str = "user_direct",
    channel_trust: str = "command",
    confirmation_status: str = "user_asserted",
    user_id: str | None = None,
    workspace_id: str | None = None,
) -> MemoryEntry:
    source_type = "user"
    if source_origin.startswith("external_"):
        source_type = "external"
    elif source_origin == "consolidation_derived":
        source_type = "inferred"
    decision = manager.write_with_provenance(
        entry_type=entry_type,
        key=key,
        value=value,
        source=MemorySource(origin=source_type, source_id=source_id, extraction_method="manual"),
        source_origin=source_origin,  # type: ignore[arg-type]
        channel_trust=channel_trust,  # type: ignore[arg-type]
        confirmation_status=confirmation_status,  # type: ignore[arg-type]
        source_id=source_id,
        scope="user",
        confidence=0.95,
        confirmation_satisfied=True,
        supersedes=supersedes,
        user_id=user_id,
        workspace_id=workspace_id,
    )
    assert decision.entry is not None
    return decision.entry


class _GraphHarness(MemoryImplMixin):
    def __init__(self, manager: MemoryManager) -> None:
        self._memory_manager = manager


@pytest.mark.asyncio
async def test_m7_graph_surfaces_scope_to_owner_tuple(tmp_path: Path) -> None:
    manager = MemoryManager(tmp_path / "memory")
    owner_entry = _write_fact(
        manager,
        key="project:alpha-owner",
        value="AlphaGraphToken belongs to owner one.",
        source_id="graph-owner-one",
        user_id="user-1",
        workspace_id="ws-1",
    )
    other_entry = _write_fact(
        manager,
        key="project:alpha-other",
        value="AlphaGraphToken belongs to owner two.",
        source_id="graph-owner-two",
        user_id="user-2",
        workspace_id="ws-1",
    )
    harness = _GraphHarness(manager)

    unscoped = await harness.do_graph_export({"format": "json"})
    unscoped_data = json.loads(str(unscoped["data"]))
    unscoped_evidence_ids = {
        evidence_id for node in unscoped_data["nodes"] for evidence_id in node["evidence_entry_ids"]
    }
    assert owner_entry.id not in unscoped_evidence_ids
    assert other_entry.id not in unscoped_evidence_ids

    exported = await harness.do_graph_export(
        {
            "format": "json",
            "user_id": "user-1",
            "workspace_id": "ws-1",
        }
    )
    exported_data = json.loads(str(exported["data"]))
    evidence_ids = {
        evidence_id for node in exported_data["nodes"] for evidence_id in node["evidence_entry_ids"]
    }
    assert owner_entry.id in evidence_ids
    assert other_entry.id not in evidence_ids

    queried = await harness.do_graph_query(
        {
            "entity": "AlphaGraphToken",
            "limit": 10,
            "user_id": "user-1",
            "workspace_id": "ws-1",
        }
    )
    query_evidence_ids = {
        evidence_id
        for collection_name in ("nodes", "edges")
        for item in queried[collection_name]
        for evidence_id in item["evidence_entry_ids"]
    }
    assert owner_entry.id in query_evidence_ids
    assert other_entry.id not in query_evidence_ids


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
    assert query.derived is True
    assert query.schema_version == "shisad.memory.graph.v1"
    assert query.build_version
    assert any(edge.relation == "related_to" for edge in query.edges)
    assert all(edge.evidence_entry_ids for edge in query.edges)

    exported = json.loads(graph.export(format="json"))
    assert exported["derived"] is True
    assert exported["schema_version"] == query.schema_version
    assert exported["build_version"] == query.build_version
    assert any(node["entity_id"] == shisad_id for node in exported["nodes"])
    assert "Evidence" in graph.export(format="md")

    shisad.importance_weight = 1.7
    manager._persist_entry(shisad)
    changed = build_knowledge_graph(manager.list_entries(limit=10))
    assert changed.build_version != graph.build_version


def test_m5_knowledge_graph_current_view_excludes_superseded_entries(
    tmp_path: Path,
) -> None:
    manager = MemoryManager(tmp_path / "memory")
    stale = _write_fact(
        manager,
        key="work:acme",
        value="I work at ACME as VP Eng.",
        entry_type="persona_fact",
        source_id="graph-superseded-old",
    )
    replacement = _write_fact(
        manager,
        key="work:acme",
        value="I no longer work at ACME.",
        entry_type="persona_fact",
        source_id="graph-superseded-new",
        supersedes=stale.id,
    )

    graph = build_knowledge_graph(manager.list_entries(limit=10))
    exported = json.loads(graph.export(format="json"))
    evidence_ids = {
        evidence_id for node in exported["nodes"] for evidence_id in node["evidence_entry_ids"]
    }

    assert stale.id not in evidence_ids
    assert replacement.id in evidence_ids


def test_m8_knowledge_graph_exports_correction_lineage_for_replacements(
    tmp_path: Path,
) -> None:
    manager = MemoryManager(tmp_path / "memory")
    stale = _write_fact(
        manager,
        key="project:acme",
        value="AcmeGraphToken ships the old release plan.",
        source_id="graph-corrected-old",
    )
    replacement = _write_fact(
        manager,
        key="project:acme",
        value="AcmeGraphToken ships the corrected release plan.",
        source_id="graph-corrected-new",
        supersedes=stale.id,
    )

    graph = build_knowledge_graph(manager.list_entries(limit=10))
    exported = json.loads(graph.export(format="json"))
    acme_node = next(
        item for item in exported["nodes"] if item["entity_id"] == graph.entity_id_for("acme")
    )

    assert stale.id not in acme_node["evidence_entry_ids"]
    assert replacement.id in acme_node["evidence_entry_ids"]
    assert acme_node["superseded_entry_ids"] == [stale.id]


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


def test_m5_knowledge_graph_aggregates_provenance_and_trust_conservatively(
    tmp_path: Path,
) -> None:
    manager = MemoryManager(tmp_path / "memory")
    _write_fact(
        manager,
        key="project:shisad",
        value="Shisad uses MemoryPack for release recall.",
        source_id="graph-provenance-elevated",
        source_origin="user_direct",
        channel_trust="command",
        confirmation_status="user_asserted",
    )
    _write_fact(
        manager,
        key="component:memorypack",
        value="MemoryPack supports Shisad release recall.",
        source_id="graph-provenance-untrusted",
        source_origin="consolidation_derived",
        channel_trust="consolidation",
        confirmation_status="auto_accepted",
    )

    graph = build_knowledge_graph(manager.list_entries(limit=10))
    exported = json.loads(graph.export(format="json"))
    shisad_id = graph.entity_id_for("Shisad")
    memory_pack_id = graph.entity_id_for("MemoryPack")
    node = next(item for item in exported["nodes"] if item["entity_id"] == shisad_id)
    edge = next(
        item
        for item in exported["edges"]
        if {item["source_id"], item["target_id"]} == {shisad_id, memory_pack_id}
    )

    assert node["source_origin"] == "mixed"
    assert node["trust_band"] == "untrusted"
    assert edge["source_origin"] == "mixed"
    assert edge["trust_band"] == "untrusted"


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
