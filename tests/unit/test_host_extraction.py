"""Host extraction regression coverage."""

from __future__ import annotations

from shisad.security.host_extraction import extract_hosts_from_text


def test_gh13_extract_hosts_ignores_redacted_pseudo_url_without_crashing() -> None:
    text = "Detail: https://www.hareruyamtg.[REDACTED:high_entropy_secret]"

    assert extract_hosts_from_text(text) == set()


def test_gh13_extract_hosts_still_reads_clean_url_near_redacted_pseudo_url() -> None:
    text = (
        "Clean detail: https://www.hareruyamtg.com/en/events/569818/detail "
        "broken mirror: https://www.hareruyamtg.[REDACTED:high_entropy_secret]"
    )

    assert extract_hosts_from_text(text) == {"www.hareruyamtg.com"}
