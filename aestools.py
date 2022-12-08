import sys
import os
import pbkdf2
import binascii
import secrets
import pyaes


SALTED_KEY_FILE = './secret-salted.key'
INITIAL_VECTOR_FILE = './initial-vector.bin'


def main():
    # Check if the key is salted before or not
    if not os.path.isfile(SALTED_KEY_FILE):
        # Read the key from the file
        with open('./secret.key', 'r') as key_file:
            key = key_file.read().strip()

        # Create 16 byte salt using os lib
        salt = os.urandom(16)

        # Expand the key to 256 bits (32 Bytes)
        key = pbkdf2.PBKDF2(key, salt).read(32)

        # Write the salted key to the file
        with open(SALTED_KEY_FILE, 'wb') as key_file:
            key_file.write(key)
    else:
        # Read the key from the secret-salted.key file
        with open(SALTED_KEY_FILE, 'rb') as key_file:
            key = key_file.read()

    # Show HEX representation of the key
    hex_key = binascii.hexlify(key)
    print(f'Algorithm key is: {hex_key}')

    # Read the file to encrypt
    with open('./my_file.txt', 'r') as plain_file:
        file_content = plain_file.read()

    # If initial-vector.bin file exists, read it else create it
    if os.path.isfile(INITIAL_VECTOR_FILE):
        with open(INITIAL_VECTOR_FILE, 'r') as iv_file:
            iv = int(iv_file.read())
    else:
        # Create initialization vector for CTR mode
        iv = secrets.randbits(256)
        with open(INITIAL_VECTOR_FILE, 'w') as iv_file:
            iv_file.write(str(iv))

    # AES 256 CTR mode
    aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(iv))
    encrypted = aes.encrypt(file_content)
    print(f'Encrypted file is: {encrypted}')

    # Write the encrypted file
    with open('./my_file.txt.enc', 'wb') as enc_file:
        enc_file.write(encrypted)


if __name__ == '__main__':
    sys.exit(main())
