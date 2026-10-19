"""Shamir's Secret Sharing for a 256-bit master key.

PyCryptodome's Shamir works on 16-byte secrets, so the 32-byte key is split
as two independent 128-bit halves. Each key service receives both halves
for the same x-coordinate (index). Document this as a key technical decision.

NOTE: combine() with fewer than `threshold` shares does NOT raise an error,
it silently returns a wrong value. Correctness is detected later, when the
wrapped DEK fails its GCM tag check.
"""
from dataclasses import dataclass

from Crypto.Protocol.SecretSharing import Shamir

KEY_SIZE = 32
HALF = 16


@dataclass(frozen=True)
class KeyShare:
    index: int          # 1..n, the x-coordinate
    left: bytes         # share of key[0:16]
    right: bytes        # share of key[16:32]
    key_version: int = 1

    def to_hex(self) -> str:
        return f"{self.index}:{self.key_version}:{self.left.hex()}:{self.right.hex()}"

    @classmethod
    def from_hex(cls, value: str) -> "KeyShare":
        idx, ver, left, right = value.split(":")
        return cls(int(idx), bytes.fromhex(left), bytes.fromhex(right), int(ver))


class ShamirKeySplitter:
    def __init__(self, threshold: int = 5, total: int = 8) -> None:
        if not 1 < threshold <= total <= 255:
            raise ValueError("require 1 < threshold <= total <= 255")
        self.threshold = threshold
        self.total = total

    def split(self, key: bytes, key_version: int = 1) -> list[KeyShare]:
        if len(key) != KEY_SIZE:
            raise ValueError("master key must be 32 bytes")
        left = Shamir.split(self.threshold, self.total, key[:HALF])
        right = Shamir.split(self.threshold, self.total, key[HALF:])
        return [KeyShare(l_idx, l_share, r_share, key_version)
                for (l_idx, l_share), (r_idx, r_share) in zip(left, right)
                if l_idx == r_idx]

    def combine(self, shares: list[KeyShare]) -> bytes:
        unique = {s.index: s for s in shares}
        if len(unique) < self.threshold:
            raise ValueError(f"need at least {self.threshold} distinct shares")
        if len({s.key_version for s in unique.values()}) != 1:
            raise ValueError("shares belong to different key versions")
        chosen = list(unique.values())[: self.threshold]
        left = Shamir.combine([(s.index, s.left) for s in chosen])
        right = Shamir.combine([(s.index, s.right) for s in chosen])
        return left + right
