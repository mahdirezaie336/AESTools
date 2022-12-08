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

Simply run the `aestools.py` file:

```bash
python3 aestools.py
```
