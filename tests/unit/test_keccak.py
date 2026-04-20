"""Known-answer vectors for the local Keccak-256 primitive."""

from __future__ import annotations

from shisad.core._keccak import keccak_256


def test_keccak_256_matches_ethereum_known_answer_vectors() -> None:
    vectors = [
        (
            b"",
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        ),
        (
            b"abc",
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
        ),
        (
            b"a" * 200,
            "96ea54061def936c4be90b518992fdc6f12f535068a256229aca54267b4d084d",
        ),
    ]

    for message, expected_hex in vectors:
        assert keccak_256(message).hex() == expected_hex
