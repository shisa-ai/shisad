"""Minimal pure-Python Keccak-256 (Ethereum-compatible, NOT SHA3-256).

Used exclusively for verifying Ethereum personal-sign signatures from
Ledger hardware devices.  Keccak-256 differs from NIST SHA3-256 only in
the padding byte (0x01 vs 0x06).

No external dependency required — avoids expanding the supply chain for
an algorithm that is only exercised in the Ledger signer verification
path.
"""

from __future__ import annotations

_MASK64 = (1 << 64) - 1

# Keccak-f[1600] 24 round constants.
_RC: tuple[int, ...] = (
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
)

# Per-lane rotation offsets, indexed by x + 5*y (x=0..4, y=0..4).
_ROT: tuple[int, ...] = (
    0,
    1,
    62,
    28,
    27,
    36,
    44,
    6,
    55,
    20,
    3,
    10,
    43,
    25,
    39,
    41,
    45,
    15,
    21,
    8,
    18,
    2,
    61,
    56,
    14,
)


def _rot64(x: int, n: int) -> int:
    return ((x << n) | (x >> (64 - n))) & _MASK64


def _keccak_f1600(state: list[int]) -> None:
    """Keccak-f[1600] permutation in-place on 25 64-bit lanes."""
    for rc in _RC:
        # theta
        c = [
            state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
            for x in range(5)
        ]
        d = [c[(x - 1) % 5] ^ _rot64(c[(x + 1) % 5], 1) for x in range(5)]
        for i in range(25):
            state[i] ^= d[i % 5]

        # rho + pi (combined)
        b = [0] * 25
        for i in range(25):
            x, y = i % 5, i // 5
            b[y + 5 * ((2 * x + 3 * y) % 5)] = _rot64(state[i], _ROT[i])

        # chi
        for i in range(25):
            x, y = i % 5, i // 5
            state[i] = b[i] ^ ((b[(x + 1) % 5 + y * 5] ^ _MASK64) & b[(x + 2) % 5 + y * 5])

        # iota
        state[0] ^= rc


def keccak_256(data: bytes) -> bytes:
    """Compute Keccak-256 digest (Ethereum-compatible).

    Returns a 32-byte digest.  Uses Keccak padding (0x01) rather than
    NIST SHA3-256 padding (0x06).
    """
    rate = 136  # (1600 - 2*256) // 8 = 136 bytes
    state = [0] * 25

    # Pad: append 0x01, then zeros, then set high bit of last byte.
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % rate != 0:
        padded.append(0x00)
    padded[-1] |= 0x80

    # Absorb.
    for offset in range(0, len(padded), rate):
        block = padded[offset : offset + rate]
        for i in range(rate // 8):
            state[i] ^= int.from_bytes(block[i * 8 : (i + 1) * 8], "little")
        _keccak_f1600(state)

    # Squeeze (32 bytes = 4 lanes).
    return b"".join(state[i].to_bytes(8, "little") for i in range(4))
