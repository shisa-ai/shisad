"""Adversarial attachment ingest regressions."""

from __future__ import annotations

from pathlib import Path

from shisad.core.attachments import AttachmentIngestor
from shisad.core.evidence import ArtifactLedger, ArtifactLifecycleState
from shisad.core.types import SessionId
from shisad.security.firewall import ContentFirewall


def _ingestor(tmp_path: Path) -> AttachmentIngestor:
    return AttachmentIngestor(
        roots=[tmp_path],
        evidence_store=ArtifactLedger(tmp_path / "evidence", salt=b"a" * 32),
        firewall=ContentFirewall(),
    )


def test_m74_malformed_png_attachment_is_quarantined_and_not_readable(
    tmp_path: Path,
) -> None:
    hostile = tmp_path / "invoice.png"
    hostile.write_bytes(b"\x89PNG\r\n\x1a\nnot-an-ihdr")

    ingestor = _ingestor(tmp_path)
    result = ingestor.ingest_path(
        session_id=SessionId("s1"),
        path=str(hostile),
        declared_mime_type="image/png",
    )

    assert result["ok"] is True
    assert result["status"] == "quarantined"
    assert result["quarantine_reason"] == "malformed_image_header"
    ref_id = str(result["evidence_ref_id"])
    ref = ingestor.evidence_store.get_ref_metadata(SessionId("s1"), ref_id)
    assert ref is not None
    assert ref.lifecycle_state == ArtifactLifecycleState.QUARANTINED
    assert ingestor.evidence_store.read(SessionId("s1"), ref_id) is None
