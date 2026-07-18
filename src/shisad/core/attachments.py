"""Bounded attachment ingest primitives for images and voice recordings."""

from __future__ import annotations

import hashlib
import json
import struct
import wave
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from typing import Any

from shisad.assistant.boundary_helpers import _is_within, _read_limited
from shisad.core.evidence import ArtifactLedger, ArtifactLifecycleState
from shisad.core.types import SessionId, TaintLabel
from shisad.security.firewall import ContentFirewall


@dataclass(frozen=True, slots=True)
class AttachmentIngestPolicy:
    """Bounds for the first image/voice attachment ingest slice."""

    max_image_bytes: int = 10_000_000
    max_audio_bytes: int = 25_000_000
    max_image_pixels: int = 25_000_000
    max_audio_duration_seconds: float = 15 * 60
    max_transcript_chars: int = 200_000
    transcript_risk_threshold: float = 0.25


@dataclass(frozen=True, slots=True)
class _DetectedAttachment:
    kind: str
    mime_type: str
    metadata: dict[str, Any]


class AttachmentIngestor:
    """Classify and persist tainted attachment manifests without decoding media."""

    def __init__(
        self,
        *,
        roots: list[Path],
        evidence_store: ArtifactLedger,
        firewall: ContentFirewall,
        policy: AttachmentIngestPolicy | None = None,
    ) -> None:
        self._roots = [root.expanduser().resolve() for root in roots]
        self._evidence_store = evidence_store
        self._firewall = firewall
        self._policy = policy or AttachmentIngestPolicy()

    @property
    def evidence_store(self) -> ArtifactLedger:
        return self._evidence_store

    def ingest_path(
        self,
        *,
        session_id: SessionId,
        path: str,
        declared_mime_type: str = "",
        filename: str = "",
        transcript_text: str = "",
        max_bytes: int | None = None,
    ) -> dict[str, Any]:
        resolved = self._resolve_path(path)
        if isinstance(resolved, dict):
            return resolved
        if not resolved.exists():
            return self._error("path_not_found", path=str(resolved))
        if not resolved.is_file():
            return self._error("not_a_file", path=str(resolved))

        display_filename = self._safe_filename(filename or resolved.name)
        declared_mime = declared_mime_type.strip().lower()
        hint = self._kind_hint(declared_mime=declared_mime, filename=display_filename)
        byte_limit = self._byte_limit(kind_hint=hint, max_bytes=max_bytes)
        try:
            size_bytes = resolved.stat().st_size
            with resolved.open("rb") as handle:
                payload, truncated = _read_limited(handle, limit=byte_limit)
        except OSError:
            return self._error("read_failed", path=str(resolved))

        hash_scope = "full"
        sha256 = hashlib.sha256(payload).hexdigest()
        detected: _DetectedAttachment | None = None
        quarantine_reason = ""
        if truncated or size_bytes > byte_limit:
            hash_scope = "first_bytes"
            quarantine_reason = "attachment_too_large"
        else:
            detected, quarantine_reason = self._detect(payload)
            if detected is not None:
                mismatch_reason = self._declared_mismatch_reason(declared_mime, detected)
                if mismatch_reason:
                    quarantine_reason = mismatch_reason
                elif detected.kind == "image":
                    if size_bytes > max(1, int(self._policy.max_image_bytes)):
                        quarantine_reason = "attachment_too_large"
                    else:
                        pixels = int(detected.metadata.get("width", 0)) * int(
                            detected.metadata.get("height", 0)
                        )
                        if pixels > max(1, int(self._policy.max_image_pixels)):
                            quarantine_reason = "image_dimensions_too_large"
                elif detected.kind == "voice":
                    if size_bytes > max(1, int(self._policy.max_audio_bytes)):
                        quarantine_reason = "attachment_too_large"
                    else:
                        duration = float(detected.metadata.get("duration_seconds", 0.0) or 0.0)
                        max_duration = max(0.1, float(self._policy.max_audio_duration_seconds))
                        if duration > max_duration:
                            quarantine_reason = "audio_duration_too_long"

        transcript = self._screen_transcript(transcript_text)
        if transcript["status"] == "quarantined" and not quarantine_reason:
            quarantine_reason = str(
                transcript.get("quarantine_reason") or "transcript_firewall_risk"
            )

        status = "quarantined" if quarantine_reason else "active"
        lifecycle_state = (
            ArtifactLifecycleState.QUARANTINED
            if status == "quarantined"
            else ArtifactLifecycleState.ACTIVE
        )
        manifest = {
            "schema_version": "shisad.attachment.v1",
            "status": status,
            "quarantine_reason": quarantine_reason,
            "kind": detected.kind if detected is not None else hint or "unknown",
            "path": str(resolved),
            "filename": display_filename,
            "declared_mime_type": declared_mime,
            "detected_mime_type": detected.mime_type if detected is not None else "",
            "size_bytes": size_bytes,
            "sha256": sha256,
            "sha256_scope": hash_scope,
            "metadata": detected.metadata if detected is not None else {},
            "transcript": transcript,
        }
        manifest_text = json.dumps(manifest, ensure_ascii=True, sort_keys=True)
        ref = self._evidence_store.store(
            session_id,
            manifest_text,
            taint_labels={TaintLabel.UNTRUSTED},
            source=f"attachment:{display_filename}",
            summary=self._summary(manifest),
            artifact_kind="attachment",
            lifecycle_state=lifecycle_state,
        )
        return {
            "ok": True,
            "status": status,
            "quarantined": status == "quarantined",
            "quarantine_reason": quarantine_reason,
            "kind": manifest["kind"],
            "path": str(resolved),
            "filename": display_filename,
            "declared_mime_type": declared_mime,
            "detected_mime_type": manifest["detected_mime_type"],
            "size_bytes": size_bytes,
            "sha256": sha256,
            "sha256_scope": hash_scope,
            "metadata": manifest["metadata"],
            "transcription_status": transcript["status"],
            "evidence_ref_id": ref.ref_id,
            "evidence_lifecycle_state": ref.lifecycle_state.value,
            "taint_labels": [TaintLabel.UNTRUSTED.value],
            "error": "",
        }

    def _resolve_path(self, value: str) -> Path | dict[str, Any]:
        if not self._roots:
            return self._error("attachment_fs_roots_unconfigured", path=value)
        candidate = Path(value).expanduser()
        if not candidate.is_absolute():
            candidate = self._roots[0] / candidate
        resolved = candidate.resolve()
        if not any(_is_within(resolved, root) for root in self._roots):
            return self._error("path_not_allowlisted", path=str(resolved))
        return resolved

    def _byte_limit(self, *, kind_hint: str, max_bytes: int | None) -> int:
        policy_limit = self._policy_byte_limit(kind_hint=kind_hint)
        if max_bytes is not None:
            return max(1, min(int(max_bytes), policy_limit))
        return policy_limit

    def _policy_byte_limit(self, *, kind_hint: str) -> int:
        if kind_hint == "image":
            return max(1, int(self._policy.max_image_bytes))
        if kind_hint == "voice":
            return max(1, int(self._policy.max_audio_bytes))
        return max(1, int(max(self._policy.max_image_bytes, self._policy.max_audio_bytes)))

    def _detect(self, payload: bytes) -> tuple[_DetectedAttachment | None, str]:
        image, image_reason = self._detect_image(payload)
        if image is not None or image_reason:
            return image, image_reason
        voice, voice_reason = self._detect_voice(payload)
        if voice is not None or voice_reason:
            return voice, voice_reason
        return None, "unsupported_attachment_type"

    def _detect_image(self, payload: bytes) -> tuple[_DetectedAttachment | None, str]:
        if payload.startswith(b"\x89PNG\r\n\x1a\n"):
            if len(payload) < 33 or payload[12:16] != b"IHDR":
                return None, "malformed_image_header"
            width, height = struct.unpack(">II", payload[16:24])
            if width <= 0 or height <= 0:
                return None, "malformed_image_header"
            return _DetectedAttachment(
                "image",
                "image/png",
                {"width": width, "height": height, "format": "png"},
            ), ""
        if payload.startswith((b"GIF87a", b"GIF89a")):
            if len(payload) < 10:
                return None, "malformed_image_header"
            width, height = struct.unpack("<HH", payload[6:10])
            if width <= 0 or height <= 0:
                return None, "malformed_image_header"
            return _DetectedAttachment(
                "image",
                "image/gif",
                {"width": width, "height": height, "format": "gif"},
            ), ""
        if payload.startswith(b"\xff\xd8"):
            return self._detect_jpeg(payload)
        return None, ""

    def _detect_jpeg(self, payload: bytes) -> tuple[_DetectedAttachment | None, str]:
        cursor = 2
        while cursor + 9 < len(payload):
            if payload[cursor] != 0xFF:
                cursor += 1
                continue
            marker = payload[cursor + 1]
            cursor += 2
            if marker in {0xD8, 0xD9}:
                continue
            if cursor + 2 > len(payload):
                break
            segment_length = int.from_bytes(payload[cursor : cursor + 2], "big")
            if segment_length < 2 or cursor + segment_length > len(payload):
                break
            if marker in {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB}:
                if segment_length < 7:
                    break
                height = int.from_bytes(payload[cursor + 3 : cursor + 5], "big")
                width = int.from_bytes(payload[cursor + 5 : cursor + 7], "big")
                if width <= 0 or height <= 0:
                    break
                return _DetectedAttachment(
                    "image",
                    "image/jpeg",
                    {"width": width, "height": height, "format": "jpeg"},
                ), ""
            cursor += segment_length
        return None, "malformed_image_header"

    def _detect_voice(self, payload: bytes) -> tuple[_DetectedAttachment | None, str]:
        if len(payload) >= 12 and payload.startswith(b"RIFF") and payload[8:12] == b"WAVE":
            try:
                with wave.open(BytesIO(payload), "rb") as wav:
                    frames = wav.getnframes()
                    rate = wav.getframerate()
                    duration = float(frames) / float(rate) if rate > 0 else 0.0
                    metadata = {
                        "format": "wav",
                        "channels": wav.getnchannels(),
                        "sample_rate_hz": rate,
                        "sample_width_bytes": wav.getsampwidth(),
                        "duration_seconds": duration,
                    }
            except (EOFError, wave.Error):
                return None, "malformed_audio_header"
            return _DetectedAttachment("voice", "audio/wav", metadata), ""
        if payload.startswith(b"OggS"):
            return _DetectedAttachment("voice", "audio/ogg", {"format": "ogg"}), ""
        if payload.startswith(b"ID3"):
            if self._looks_like_id3_mp3(payload):
                return _DetectedAttachment("voice", "audio/mpeg", {"format": "mp3"}), ""
            return None, "malformed_audio_header"
        if self._looks_like_mp3_frame(payload):
            return _DetectedAttachment("voice", "audio/mpeg", {"format": "mp3"}), ""
        if len(payload) >= 12 and payload[4:8] == b"ftyp":
            major = payload[8:12].decode("ascii", errors="ignore").strip()
            if major in {"M4A", "M4B", "mp42", "isom"}:
                return _DetectedAttachment("voice", "audio/mp4", {"format": major or "mp4"}), ""
        return None, ""

    def _screen_transcript(self, transcript_text: str) -> dict[str, Any]:
        text = transcript_text.strip()
        if not text:
            return {
                "status": "not_provided",
                "text": "",
                "quarantine_reason": "",
                "risk_score": 0.0,
                "risk_factors": [],
                "taint_labels": [TaintLabel.UNTRUSTED.value],
            }
        max_chars = max(1, int(self._policy.max_transcript_chars))
        if len(text) > max_chars:
            return {
                "status": "quarantined",
                "text": "",
                "quarantine_reason": "transcript_too_large",
                "risk_score": 1.0,
                "risk_factors": ["transcript_too_large"],
                "taint_labels": [TaintLabel.UNTRUSTED.value],
                "original_char_count": len(text),
                "max_transcript_chars": max_chars,
            }
        result = self._firewall.inspect(text, trusted_input=False)
        risky = bool(result.risk_factors or result.secret_findings) or (
            result.risk_score >= float(self._policy.transcript_risk_threshold)
        )
        return {
            "status": "quarantined" if risky else "provided",
            "text": result.sanitized_text,
            "quarantine_reason": "transcript_firewall_risk" if risky else "",
            "risk_score": result.risk_score,
            "risk_factors": list(result.risk_factors),
            "taint_labels": [label.value for label in result.taint_labels],
        }

    @staticmethod
    def _looks_like_mp3_frame(payload: bytes) -> bool:
        if len(payload) < 4:
            return False
        if payload[0] != 0xFF or (payload[1] & 0xE0) != 0xE0:
            return False
        version = (payload[1] >> 3) & 0x03
        layer = (payload[1] >> 1) & 0x03
        bitrate_index = (payload[2] >> 4) & 0x0F
        sample_rate_index = (payload[2] >> 2) & 0x03
        return (
            version != 0x01
            and layer != 0x00
            and bitrate_index not in {0x00, 0x0F}
            and sample_rate_index != 0x03
        )

    @classmethod
    def _looks_like_id3_mp3(cls, payload: bytes) -> bool:
        if len(payload) < 14 or not payload.startswith(b"ID3"):
            return False
        major_version = payload[3]
        flags = payload[5]
        if major_version not in {3, 4} or payload[4] == 0xFF:
            return False
        if major_version == 3 and flags & 0x1F:
            return False
        if major_version == 4 and flags & 0x1F:
            return False
        size_bytes = payload[6:10]
        if any(byte & 0x80 for byte in size_bytes):
            return False
        tag_payload_size = 0
        for byte in size_bytes:
            tag_payload_size = (tag_payload_size << 7) | byte
        tag_size = 10 + tag_payload_size
        if tag_size >= len(payload):
            return False
        return cls._looks_like_mp3_frame(payload[tag_size:])

    @staticmethod
    def _declared_mismatch_reason(
        declared_mime: str,
        detected: _DetectedAttachment,
    ) -> str:
        if not declared_mime:
            return ""
        if declared_mime == detected.mime_type:
            return ""
        declared_family = declared_mime.split("/", 1)[0]
        detected_family = detected.mime_type.split("/", 1)[0]
        if declared_family and detected_family and declared_family != detected_family:
            return "mime_mismatch"
        if declared_family in {"image", "audio"}:
            return "mime_mismatch"
        return ""

    @staticmethod
    def _kind_hint(*, declared_mime: str, filename: str) -> str:
        lowered_name = filename.lower()
        if declared_mime.startswith("image/") or lowered_name.endswith(
            (".png", ".jpg", ".jpeg", ".gif")
        ):
            return "image"
        if declared_mime.startswith("audio/") or lowered_name.endswith(
            (".wav", ".ogg", ".opus", ".mp3", ".m4a", ".mp4")
        ):
            return "voice"
        return ""

    @staticmethod
    def _safe_filename(value: str) -> str:
        name = Path(value.strip() or "attachment").name.strip()
        return name or "attachment"

    @staticmethod
    def _summary(manifest: dict[str, Any]) -> str:
        status = str(manifest.get("status", "unknown"))
        kind = str(manifest.get("kind", "attachment"))
        mime_type = str(manifest.get("detected_mime_type") or manifest.get("declared_mime_type"))
        size_bytes = int(manifest.get("size_bytes", 0) or 0)
        reason = str(manifest.get("quarantine_reason", "")).strip()
        base = f"{kind} attachment {mime_type or 'unknown'} {size_bytes} bytes {status}"
        return f"{base}: {reason}" if reason else base

    @staticmethod
    def _error(reason: str, *, path: str) -> dict[str, Any]:
        return {
            "ok": False,
            "status": "rejected",
            "quarantined": False,
            "quarantine_reason": "",
            "kind": "unknown",
            "path": path,
            "filename": Path(path).name,
            "declared_mime_type": "",
            "detected_mime_type": "",
            "size_bytes": 0,
            "sha256": "",
            "sha256_scope": "",
            "metadata": {},
            "transcription_status": "not_provided",
            "evidence_ref_id": "",
            "evidence_lifecycle_state": "",
            "taint_labels": [TaintLabel.UNTRUSTED.value],
            "error": reason,
        }
