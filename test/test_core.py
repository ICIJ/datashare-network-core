from unittest import TestCase

from dsnet.core import PigeonHole
from dsnet.crypto import gen_key_pair, compute_dhke


class TestPigeonHole(TestCase):
    def setUp(self) -> None:
        self.bob_keys = gen_key_pair()
        self.query_keys = gen_key_pair()
        self.ph_alice = PigeonHole(compute_dhke(self.query_keys.private, self.bob_keys.public), self.query_keys.public)
        self.ph_bob = PigeonHole(compute_dhke(self.bob_keys.private, self.query_keys.public), self.query_keys.public)

    def test_alice_sends_query_to_bob(self):
        encrypted_message = self.ph_alice.encrypt('message')
        self.assertEqual('message', self.ph_bob.decrypt(encrypted_message))

    def test_bob_responds_to_alice(self):
        encrypted_response = self.ph_bob.encrypt('response')
        self.assertEqual('response', self.ph_alice.decrypt(encrypted_response))




