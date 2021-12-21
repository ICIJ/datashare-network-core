from unittest import TestCase

from dsnet.core import PigeonHole, Conversation
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


class TestConversation(TestCase):
    def setUp(self) -> None:
        self.bob_keys = gen_key_pair()
        self.alice_keys = gen_key_pair()
        self.conversation_keys = gen_key_pair()

    def test_alice_sends_query_conversation(self):
        conversation = Conversation(self.conversation_keys.private, self.bob_keys.public, querier=True)

        query = conversation.create_query('query')

        self.assertEquals(conversation.nb_recv_messages, 0)
        self.assertEquals(conversation.nb_sent_messages, 1)
        self.assertEquals(self.conversation_keys.public, query.public_key)
        self.assertEquals('query', query.payload)
        self.assertIsNotNone(conversation.last_address)

    def test_bob_receives_query_conversation(self):
        alice_conversation = Conversation(self.conversation_keys.private, self.bob_keys.public, querier=True)
        query = alice_conversation.create_query('query')
        conversation = Conversation(self.bob_keys.private, self.conversation_keys.public)

        conversation.add_query(query)
        response = conversation.create_response('bob query response')

        self.assertEquals(conversation.nb_recv_messages, 1)
        self.assertEquals(conversation.nb_sent_messages, 1)
        self.assertEquals(alice_conversation.last_address, response.address)
        self.assertIsNotNone(response.payload)

    def test_alice_decrypt_message_from_bob(self):
        alice_conversation = Conversation(self.conversation_keys.private, self.bob_keys.public, querier=True)
        query = alice_conversation.create_query('query')
        bob_conversation = Conversation(self.bob_keys.private, self.conversation_keys.public)
        bob_conversation.add_query(query)
        response = bob_conversation.create_response('response')

        alice_conversation.add_message(response)

        self.assertEquals(alice_conversation.nb_recv_messages, 1)
        self.assertEquals(alice_conversation.nb_sent_messages, 1)
        self.assertEquals('response', alice_conversation.last_message)

    def test_bob_decrypt_message_from_alice(self):
        alice_conversation = Conversation(self.conversation_keys.private, self.bob_keys.public, querier=True)
        query = alice_conversation.create_query('query')
        bob_conversation = Conversation(self.bob_keys.private, self.conversation_keys.public)
        bob_conversation.add_query(query)
        message = bob_conversation.create_response('response from Bob')
        alice_conversation.add_message(message)

        response = alice_conversation.create_response('message from Alice')
        bob_conversation.add_message(response)

        self.assertEquals(bob_conversation.nb_recv_messages, alice_conversation.nb_sent_messages)
        self.assertEquals(bob_conversation.nb_sent_messages, alice_conversation.nb_recv_messages)
        self.assertEquals('message from Alice', bob_conversation.last_message)

    def test_is_receiving_address(self):
        alice_conversation = Conversation(self.conversation_keys.private, self.bob_keys.public, querier=True)
        bob_conversation = Conversation(self.bob_keys.private, self.conversation_keys.public)

        bob_conversation.add_query(alice_conversation.create_query('query'))
        response = bob_conversation.create_response('response')
        self.assertTrue(alice_conversation.is_receiving(response.address))

        message = alice_conversation.create_response('message')
        self.assertTrue(bob_conversation.is_receiving(message.address))