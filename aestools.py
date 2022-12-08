import sys
import os
import pbkdf2
import binascii
import secrets
import pyaes

# Read the key from the file
with open('./secret.key', 'r') as f:
    key = f.read().strip()

    # Create 16 byte salt using os lib
    salt = os.urandom(16)

    # Expand the key to 256 bits (32 Bytes)
    key = pbkdf2.PBKDF2(key, salt).read(32)

    # Show HEX representation of the key
    hex_key = binascii.hexlify(key)
    print(hex_key)

    # Create initialization vector for CTR mode
    iv = secrets.randbits(256)

