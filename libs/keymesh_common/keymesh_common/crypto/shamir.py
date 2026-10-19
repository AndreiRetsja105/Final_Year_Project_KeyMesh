"""Using Shamir's Secret Sharing scheme for a 256-bit master key.

The PyCryptodome library works with secrets that are 16 bytes in size;
therefore, the 32-byte master key is split into two 16-byte parts.

Each Key Service receives one share derived from the left half
and one share derived from the right half, using the same index for both """

from dataclasses import dataclass

from Crypto.Protocol.SecretSharing import Shamir

# Full-size AES-256 master key
KEY_SIZE = 32

# In PyCryptodome, Shamir's scheme works with 16-byte secrets
HALF = 16


@dataclass(frozen=True)
class KeyShare:

    # Specify a number, for example, from 1 to 8
    index: int          # 1..n, the x-coordinate

    # A share created based on the first half of the master key
    left: bytes         # share of key[0:16]
    
    # A share created based on the second half of the master key
    right: bytes        # share of key[16:32]
    
    # The version helps us avoid mixing shares that belong to different master keys 
    key_version: int = 1

    def to_hex(self) -> str:
        
        # Convert the fraction to text so that it can be saved to a file
        return f"{self.index}:{self.key_version}:{self.left.hex()}:{self.right.hex()}"

    @classmethod
    def from_hex(cls, value: str) -> "KeyShare":
        # Restore a KeyShare object from saved text
        idx, ver, left, right = value.split(":")
        
        return cls(int(idx), bytes.fromhex(left), bytes.fromhex(right), int(ver))


class ShamirKeySplitter:
    def __init__(self, threshold: int = 5, total: int = 8) -> None:
        
        # The threshold value must be correct
        # For KeyMesh, the standard configuration requires 5 out of 8 shares
        if not 1 < threshold <= total <= 255:
            raise ValueError("require 1 < threshold <= total <= 255")
        
        self.threshold = threshold
        self.total = total

    def split(self, key: bytes, key_version: int = 1) -> list[KeyShare]:

        # For AES-256, the master key must be exactly 32 bytes in size
        if len(key) != KEY_SIZE:
            raise ValueError("master key must be 32 bytes")
        
        # Divide the first 16 bytes into portions
        left = Shamir.split(self.threshold, self.total, key[:HALF])
        
        # Divide the second 16 bytes into portions
        right = Shamir.split(self.threshold, self.total, key[HALF:])
        
        # Combine the left and right segments, using the same segment index
        return [KeyShare(l_idx, l_share, r_share, key_version)
                for (l_idx, l_share), (r_idx, r_share) in zip(left, right)
                if l_idx == r_idx]

    def combine(self, shares: list[KeyShare]) -> bytes:
        # Remove duplicate elements by index
        unique = {s.index: s for s in shares}
 
        # We need to have at least a threshold number of different stocks
        if len(unique) < self.threshold:
            raise ValueError(f"need at least {self.threshold} distinct shares")
        
        # Shares belonging to different versions of a master key must not be mixed
        if len({s.key_version for s in unique.values()}) != 1:
            raise ValueError("shares belong to different key versions")
        
        # Only the necessary number of shares is required
        chosen = list(unique.values())[: self.threshold]
        
        # Recover the first half of the master key
        left = Shamir.combine([(s.index, s.left) for s in chosen])
        
        # Recover the second half of the master key
        right = Shamir.combine([(s.index, s.right) for s in chosen])
        
        # Combine both halves back into a 32-byte master key
        return left + right
