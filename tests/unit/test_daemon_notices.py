"""Daemon notice sanitization coverage."""

from shisad.core.daemon_notices import strip_daemon_lockdown_notice_suffix

_STRUCTURAL_NOTICE = (
    "[LOCKDOWN NOTICE] Session is in caution due to manual: imported.\n"
    "What should I do: keep the session locked, or clear the lockdown?"
)


def test_archive_imported_structural_lockdown_notice_strips_without_metadata() -> None:
    assert (
        strip_daemon_lockdown_notice_suffix(
            _STRUCTURAL_NOTICE,
            {"_archive_imported": True},
            role="assistant",
        )
        == ""
    )


def test_non_imported_structural_lockdown_notice_quote_is_preserved() -> None:
    content = f"The operator pasted this example:\n{_STRUCTURAL_NOTICE}"

    assert strip_daemon_lockdown_notice_suffix(content, {}, role="assistant") == content


def test_legacy_lockdown_notice_strips_without_metadata() -> None:
    content = (
        "Prior answer.\n\n"
        "[LOCKDOWN NOTICE] Session is in caution due to manual. "
        "To recover: run shisad lockdown resume when ready."
    )

    assert strip_daemon_lockdown_notice_suffix(content, {}, role="assistant") == "Prior answer."
