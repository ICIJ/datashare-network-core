"""
Cryptographic operations.
"""

import random
import re
import struct
from hashlib import sha256
from secrets import token_bytes
from typing import NamedTuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    Encoding,
    load_pem_private_key,
    NoEncryption,
    PrivateFormat,
    PublicFormat
)

# Cryptographically secure pseudo-random generator.
from sscred import AbeSignature

RNG = random.SystemRandom()


ADDRESS_LENGTH = 32
ADDRESS_PREFIX = b"addr"
KEY_PREFIX = b"key"
MESSAGE_NUM_FORMAT = "!Q"
PUBLIC_KEY_LENGTH: int = 32
SECRET_KEY_LENGTH: int = 32
SIGNATURE_LENGTH: int = 64
NONCE_LENGTH = 12
PADDING_SEP = b"\x80"
PADDING_BYTE = b"\x00"
PADDING_PATTERN = re.compile(PADDING_SEP + PADDING_BYTE + b"*$")

ENCRYPTION_KEY_LENGTH = 32
ENCRYPTION_METADATA_LENGTH = 28


class KeyPair(NamedTuple):
    secret: bytes
    public: bytes


def _hash_everything(*args: bytes) -> bytes:
    """
    Hash every bytes passed in parameters.
    """

    digest = sha256()
    for arg in args:
        digested_arg = sha256(arg).digest()
        digest.update(digested_arg)
    return digest.digest()


def compute_address(key_dh: bytes, public_key: bytes, message_num: int) -> bytes:
    """
    Compute the address where a message should be sent.

    :param key_dh: key obtained by computing the Diffie-Hellman
    :param public_key: public key of the sender of the message
    :param message_num: message number
    :return: address to send or retrieve the message
    """

    message_num_b = struct.pack(MESSAGE_NUM_FORMAT, message_num)
    return _hash_everything(ADDRESS_PREFIX, key_dh, public_key, message_num_b)


def compute_sym_key(key_dh: bytes, public_key: bytes, message_num: int) -> bytes:
    """
    Compute the symmetric key used for encrypting and decrypting messages.

    :param key_dh: key obtained by computing the Diffie-Hellman
    :param public_key: public key of the sender of the message
    :param message_num: message number
    :return: key used to encrypt or decrypt the message
    """

    message_num_b = struct.pack(MESSAGE_NUM_FORMAT, message_num)
    return _hash_everything(KEY_PREFIX, key_dh, public_key, message_num_b)


def dumps_secret_key(secret_key: bytes, password: bytes) -> bytes:
    """
    Dump a secret key encrypted with a password in PEM format.

    :param secret_key: secret key to serialize
    :param password: password with which to encrypt the secret key
    :return: serialized secret key
    """

    secret_key_obj = X25519PrivateKey.from_private_bytes(secret_key)
    # TODO: Set explicitly the encryption algorithm and the encryption mode.
    encryption = BestAvailableEncryption(password)
    secret_key_b = secret_key_obj.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, encryption)
    return secret_key_b


def loads_secret_key(secret_key_pem: bytes, password: bytes) -> bytes:
    """
    Load a secret key encrypted with a password in PEM format.

    :param secret_key_pem: serialized secret key to parse
    :param password: password with which to decrypt the secret key
    :raises ValueError: the key bytes are invalid, or the password is wrong
    :return: deserialized secret key
    """

    secret_key = load_pem_private_key(secret_key_pem, password=password, backend=default_backend())
    encryption = NoEncryption()
    secret_key_b = secret_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, encryption)
    return secret_key_b


def gen_key_pair() -> KeyPair:
    """
    Generate a new key pair.

    :return: A new pair of secret key and public key.
    """

    secret_key = X25519PrivateKey.generate()
    public_key = secret_key.public_key()
    encryption = NoEncryption()

    secret_key_b = secret_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, encryption)
    public_key_b = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return KeyPair(secret_key_b, public_key_b)


def compute_dhke(secret_key: bytes, public_key: bytes) -> bytes:
    """
    Generate a shared secret with Diffie-Hellman.

    :param secret_key: secret key used to compute the Diffie-Hellman
    :param public_key: public key used to compute the Diffie-Hellman
    :return: exchange key obtained by computing a Diffie Hellman
    """

    secret_key_obj = X25519PrivateKey.from_private_bytes(secret_key)
    public_key_obj = X25519PublicKey.from_public_bytes(public_key)
    dh_key = secret_key_obj.exchange(public_key_obj)
    return dh_key


def get_public_key(secret_key: bytes) -> bytes:
    """
    Get the public key from a secret key.

    :param secret_key: Secret key from which to extract public parameters.
    :return: public key corresponding to the secret key passed in parameters
    """

    secret_key_obj = X25519PrivateKey.from_private_bytes(secret_key)
    public_key_obj = secret_key_obj.public_key()

    public_key_b = public_key_obj.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return public_key_b


def encrypt(cleartext: bytes, key: bytes) -> bytes:
    """
    Encrypt a message with a key.

    :param cleartext: cleartext to encrypt
    :param key: key to use to encrypt the cleartext
    :return: encrypted cleartext
    """

    cipher = AESGCM(key)
    nonce = token_bytes(NONCE_LENGTH)

    ciphertext = nonce + cipher.encrypt(nonce, cleartext, None)

    return ciphertext


def decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypt a message with a key.

    :param ciphertext: ciphertext to decrypt
    :param key: key to use to decrypt the ciphertext
    :return: decrypted ciphertext or None if the decryption failed
    :except: InvalidTag if decryption fails
    """

    nonce = ciphertext[:NONCE_LENGTH]
    ciphertext = ciphertext[NONCE_LENGTH:]
    cipher = AESGCM(key)

    cleartext = cipher.decrypt(nonce, ciphertext, None)

    return cleartext


def pad_message(message: bytes, target_length: int) -> bytes:
    """
    Pad a message to target length using ISO/IEC 7816-4:2005 padding.

    :param message: message to be padded
    :param target_length: length of the message after padding
    :raises InvalidPigeonholeMessage: the message is too long to be padded
    :return: padded message
    """

    diff_length = target_length - len(message) - 1
    if diff_length < 0:
        raise MessageTooLongException(len(message), target_length)

    return message + PADDING_SEP + PADDING_BYTE * (diff_length)


def unpad_message(padded_message: bytes) -> bytes:
    """
    Un-pad a message using ISO/IEC 7816-4:2005 padding.

    :param padded_message: padded message to un-pad
    :raises InvalidPigeonholeMessage: the padding of the message is invalid
    :return: un-padded message
    """
    match = PADDING_PATTERN.search(padded_message)
    if not match:
        raise InvalidPadding()

    return padded_message[:match.start()]


def gen_fake_address() -> bytes:
    """
    Generate a fake address.

    :return: fake address
    """
    return token_bytes(ADDRESS_LENGTH)


def gen_fake_encrypted_message(target_length: int) -> bytes:
    """
    Generate a fake encrypted message.

    :param target_length: length of the fake encrypted message
    :return: fake encypted message
    """

    key = token_bytes(32)
    cipher = AESGCM(key)
    nonce = token_bytes(NONCE_LENGTH)

    payload = token_bytes(target_length)

    ciphertext = nonce + cipher.encrypt(nonce, payload, None)

    return ciphertext


class MessageTooLongException(ValueError):
    """
    The message is too long for the maximum padded value
    """
    def __init__(self, size: int, target_length: int) -> None:
        super().__init__("message too long (%d) for padded limit (%d)" % (size, target_length))


class InvalidPadding(ValueError):
    """
    The message is too long for the maximum padded value
    """