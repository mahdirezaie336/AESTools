# AESTools

A tool to encrypt and decrypt files using AES-256-CTR.

## Installation

First, install the dependencies:

```bash
sudo apt-get install build-essential python3-dev \
    libldap2-dev libsasl2-dev slapd ldap-utils tox \
    lcov valgrind
```

Then, install python dependencies:

```bash
pip install -r requirements.txt
```

## Usage

To do encryption, Simply run the `aestools.py` file with this args:

```bash
python3 aestools.py <D|E> <file to decrypt/encrypt>
```

replace `<D|E>` with `D` for decrypt and `E` for encrypt and `<file to decrypt/encrypt>` with the file you want to encrypt/decrypt.
