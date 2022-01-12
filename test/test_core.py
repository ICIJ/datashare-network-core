from unittest import TestCase

from dsnet.core import PigeonHole, Conversation
from dsnet.crypto import gen_key_pair


class TestPigeonHole(TestCase):
    def setUp(self) -> None:
        self.bob_keys = gen_key_pair()
        self.query_keys = gen_key_pair()
        self.ph_alice = PigeonHole(self.bob_keys.public, self.query_keys.private, self.query_keys.public)
        self.ph_bob = PigeonHole(self.query_keys.public, self.bob_keys.private)

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
        conversation = Conversation(self.conversation_keys.private, self.bob_keys.public, query='query', querier=True)

        query = conversation.get_query()

        self.assertEqual(conversation.query, 'query')
        self.assertEqual(conversation.nb_recv_messages, 0)
        self.assertEqual(conversation.nb_sent_messages, 1)
        self.assertEqual(self.conversation_keys.public, query.public_key)
        self.assertEqual('query', query.payload)
        self.assertIsNotNone(conversation.last_address)

    def test_bob_receives_query_conversation(self):
        alice_conversation = Conversation(self.conversation_keys.private, self.bob_keys.public, query='query', querier=True)
        conversation = Conversation(self.bob_keys.private, self.conversation_keys.public, query='query')

        response = conversation.create_response('bob query response')

        self.assertEqual(conversation.nb_recv_messages, 1)
        self.assertEqual(conversation.nb_sent_messages, 1)
        self.assertEqual(alice_conversation.last_address, response.address)
        self.assertIsNotNone(response.payload)

    def test_alice_decrypt_message_from_bob(self):
        alice_conversation = Conversation(self.conversation_keys.private, self.bob_keys.public, query='query', querier=True)
        bob_conversation = Conversation(self.bob_keys.private, self.conversation_keys.public, query='query')
        response = bob_conversation.create_response('response')

        alice_conversation.add_message(response)

        self.assertEqual(alice_conversation.nb_recv_messages, 1)
        self.assertEqual(alice_conversation.nb_sent_messages, 1)
        self.assertEqual(b'response', alice_conversation.last_message.payload)

    def test_bob_decrypt_message_from_alice(self):
        alice_conversation = Conversation(self.conversation_keys.private, self.bob_keys.public, query='query', querier=True)
        bob_conversation = Conversation(self.bob_keys.private, self.conversation_keys.public, query='query')
        message = bob_conversation.create_response('response from Bob')
        alice_conversation.add_message(message)

        response = alice_conversation.create_response('message from Alice')
        bob_conversation.add_message(response)

        self.assertEqual(bob_conversation.nb_recv_messages, alice_conversation.nb_sent_messages)
        self.assertEqual(bob_conversation.nb_sent_messages, alice_conversation.nb_recv_messages)
        self.assertEqual(b'message from Alice', bob_conversation.last_message.payload)

    def test_is_receiving_address(self):
        alice_conversation = Conversation(self.conversation_keys.private, self.bob_keys.public, query='query', querier=True)
        bob_conversation = Conversation(self.bob_keys.private, self.conversation_keys.public, query='query')

        response = bob_conversation.create_response('response')
        self.assertTrue(alice_conversation.is_receiving(response.address))

        message = alice_conversation.create_response('message')
        self.assertTrue(bob_conversation.is_receiving(message.address))