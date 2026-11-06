"""Script for development (DEV) purposes only.

Generates a new master key, splits it using Shamir's scheme (5-of-8)
, and writes one of the shares to a separate file.

The master key itself is not written to disk. """
from pathlib import Path 

from keymesh_common.crypto import AesGcmCipher, ShamirKeySplitter

# Folder where created shared resources will be saved
out = Path ("secrets/shares")

# Create a folder if it does not already exist
out.mkdir(parents=True, exist_ok=True)

# Create a new master key and split it into 8 parts
# At least 5 parts will be required to reconstruct the key
# Save each share into its own file
for share in ShamirKeySplitter(5, 8).split(AesGcmCipher.generate_key()):
    (out / f"share_{share.index}.txt").write_text(share.to_hex())

# A simple message confirming that the files have been created
print(f"wrote 8 shares to {out}/")