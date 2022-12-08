import sys
import os
import pbkdf2

# Read the key from the file
with open('./secret.key', 'r') as f:
    key = f.read().strip()

    # Add 16 byte salt using os lib
    key = key.encode() + os.urandom(16)

    # Expand the key to 256 bits
    key = pbkdf2.PBKDF2(key).read(32)


