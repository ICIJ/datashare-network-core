from unittest import TestCase

from cryptography.hazmat.primitives._serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sscred import unpackb, packb

from dsnet.token import AbeToken
from test.test_core import create_tokens


class TestToken(TestCase):
    def test_equals(self):
        [token] = create_tokens(1)
        skey = Ed25519PrivateKey.from_private_bytes(token.secret_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
        actual_token = AbeToken(skey, unpackb(packb(token.token)))

        assert token == actual_token