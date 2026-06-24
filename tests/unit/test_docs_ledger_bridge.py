from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
RUNBOOK = REPO_ROOT / "docs" / "runbooks" / "LEDGER-BRIDGE.md"
RUNBOOK_INDEX = REPO_ROOT / "docs" / "runbooks" / "README.md"
TWO_FACTOR_DOC = REPO_ROOT / "docs" / "2FA.md"
ENV_VARS_DOC = REPO_ROOT / "docs" / "ENV-VARS.md"
BRIDGE_README = REPO_ROOT / "contrib" / "ledger-bridge" / "README.md"


def test_ledger_bridge_runbook_covers_remote_daemon_topology() -> None:
    assert RUNBOOK.exists()
    text = RUNBOOK.read_text(encoding="utf-8")

    required_snippets = [
        "remote shisad daemon",
        "local Ledger bridge",
        "USB HID",
        "registered public key",
        "SHISAD_SIGNER_LEDGER_URL",
        "SHISAD_SIGNER_LEDGER_BEARER_TOKEN",
        "SHISAD_LEDGER_BRIDGE_BEARER_TOKEN",
        "npx tsx src/server.ts --port 9090",
        "ssh -N -R 127.0.0.1:9090:127.0.0.1:9090",
        "Do not expose the Ledger bridge publicly",
        "npm run --silent extract-key -- > ledger-pubkey.pem",
        "shisad signer register",
        "curl -fsS",
        "shisad signer list",
        "Troubleshooting",
    ]
    for snippet in required_snippets:
        assert snippet in text


def test_ledger_bridge_runbook_is_discoverable_from_related_docs() -> None:
    for path in [RUNBOOK_INDEX, TWO_FACTOR_DOC, ENV_VARS_DOC]:
        text = path.read_text(encoding="utf-8")
        assert "LEDGER-BRIDGE.md" in text


def test_ledger_public_key_extraction_docs_use_noninteractive_npm_script() -> None:
    expected = "npm run --silent extract-key --"
    for path in [RUNBOOK, BRIDGE_README]:
        text = path.read_text(encoding="utf-8")
        assert expected in text
        assert "npx tsx src/extract-key.ts >" not in text


def test_ledger_registration_docs_describe_enforced_algorithm_contract() -> None:
    for path in [RUNBOOK, ENV_VARS_DOC]:
        text = path.read_text(encoding="utf-8")
        assert "algorithm=ecdsa-secp256k1" in text
        assert "require" in text
