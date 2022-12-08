import sys
import os
import pbkdf2
import binascii
import secrets
import pyaes


SECRET_FILE = './secret.key'
SALTED_KEY_FILE = './secret-salted.key'
INITIAL_VECTOR_FILE = './initial-vector.bin'


def read_full_file(file_name, mode):
    with open(file_name, mode) as file:
        return file.read()


def write_to_file(file_name, mode, content):
    with open(file_name, mode) as file:
        file.write(content)


def salt_key(key, salt_bytes=16):
    # Create salt using os lib
    salt = os.urandom(salt_bytes)

    # Expand the key to 256 bits (32 Bytes)
    key = pbkdf2.PBKDF2(key, salt).read(32)

    return key


def encrypt(file_to_encrypt):
    # Check if the key is salted before or not
    if os.path.isfile(SALTED_KEY_FILE):
        key = read_full_file(SALTED_KEY_FILE, 'rb')
    else:
        key = salt_key(read_full_file(SECRET_FILE, 'r').strip())
        write_to_file(SALTED_KEY_FILE, 'wb', key)

    print(f'Algorithm key is: {binascii.hexlify(key)}')

    # If initial-vector.bin file exists, read it else create it
    if os.path.isfile(INITIAL_VECTOR_FILE):
        iv = int(read_full_file(INITIAL_VECTOR_FILE, 'r'))
    else:
        iv = secrets.randbits(256)
        write_to_file(INITIAL_VECTOR_FILE, 'w', str(iv))

    # AES 256 CTR mode
    aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(iv))
    with open(file_to_encrypt, 'rb') as f1, open(file_to_encrypt + '.enc', 'wb') as f2:
        pyaes.encrypt_stream(aes, f1, f2)


def decrypt(file_to_decrypt):
    # Check if the salted key file exists
    if not os.path.isfile(SALTED_KEY_FILE):
        print('Key file does not exist. You need to provide it in "secret-salted.key" file.')
        return 1

    # Check if the initial vector file exists
    if not os.path.isfile(INITIAL_VECTOR_FILE):
        print('Initial vector file does not exist. You need to provide it in "initial-vector.bin" file.')
        return 1

    key = read_full_file(SALTED_KEY_FILE, 'rb')
    iv = int(read_full_file(INITIAL_VECTOR_FILE, 'r'))

    # AES 256 CTR mode
    aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(iv))
    with open(file_to_decrypt, 'rb') as f1, open(file_to_decrypt + '.dec', 'wb') as f2:
        pyaes.decrypt_stream(aes, f1, f2)


def main(*args):
    if args[0] == 'D':
        return decrypt(args[1])
    elif args[0] == 'E':
        return encrypt(args[1])


if __name__ == '__main__':
    # Get input args
    args = sys.argv[1:]
    if len(args) < 2:
        print('Usage: python3 aestools.py <D|E> <file to decrypt/encrypt>')
        sys.exit(1)
    else:
        sys.exit(main(*args))
