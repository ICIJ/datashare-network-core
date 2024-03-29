import datetime
from typing import List
from unittest import TestCase

from cuckoo.filter import BCuckooFilter
from sscred import AbeSignature, AbeParam, packb, AbeSigner, unpackb

from dsnet.core import PigeonHole, Conversation, PH_MESSAGE_LENGTH, QueryType, InvalidQueryType
from dsnet.crypto import gen_key_pair, pad_message
from dsnet.message import Query, PigeonHoleNotification, PigeonHoleMessage, PublicationMessage, MessageType
from dsnet.mspsi import MSPSIQuerier, MSPSIDocumentOwner, Document, NamedEntity, NamedEntityCategory
from dsnet.token import generate_commitments, generate_challenges, generate_pretokens, generate_tokens, AbeToken

SERVER_SECRET_KEY, SERVER_PUBLIC_KEY = AbeParam().generate_new_key_pair()


def gen_dummy_abe_signature():
    params = AbeParam()
    return AbeSignature(
        b"foo",
        params.group.hash_to_point(b"foo"),
        params.group.hash_to_point(b"foo1"),
        params.group.order(),
        params.group.order() * 2,
        params.group.order() * 3,
        params.group.order() * 4,
        params.group.order() * 5,
        params.group.order() * 6
    )


def create_tokens(nb: int) -> List[AbeToken]:
    signer = AbeSigner(SERVER_SECRET_KEY, SERVER_PUBLIC_KEY, disable_acl=True)
    coms, coms_internal = generate_commitments(signer, nb)
    challenges, challenges_int, token_skeys = generate_challenges(SERVER_PUBLIC_KEY, coms)
    pre_tokens = generate_pretokens(signer, challenges, coms_internal)
    return generate_tokens(SERVER_PUBLIC_KEY, challenges_int, token_skeys, pre_tokens)


class TestPigeonHole(TestCase):
    def setUp(self) -> None:
        self.bob_keys = gen_key_pair()
        self.query_keys = gen_key_pair()
        self.ph_alice_send = PigeonHole.create_querier_sending_ph(self.bob_keys.public, self.query_keys.secret, 0)
        self.ph_alice_recv = PigeonHole.create_querier_receiving_ph(self.bob_keys.public, self.query_keys.secret, 0)
        self.ph_bob_send = PigeonHole.create_respondent_sending_ph(self.query_keys.public, self.bob_keys.secret, 0)
        self.ph_bob_recv = PigeonHole.create_respondent_receiving_ph(self.query_keys.public, self.bob_keys.secret, 0)

    def test_alice_sends_query_to_bob(self):
        encrypted_message = self.ph_alice_send.encrypt(b'query')
        self.assertEqual(b'query', self.ph_bob_recv.decrypt(encrypted_message))

    def test_bob_responds_to_alice(self):
        encrypted_response = self.ph_bob_send.encrypt(b'response')
        self.assertEqual(b'response', self.ph_alice_recv.decrypt(encrypted_response))


class TestMessages(TestCase):
    def test_create_query(self):
        [token] = create_tokens(1)
        _, pkey = gen_key_pair()
        query = Query.create(pkey, token, b'payload')

        self.assertEqual(query.public_key, pkey)
        self.assertEqual(query.token, token.token)
        self.assertEqual(query.payload, b'payload')
        self.assertTrue(query.validate(SERVER_PUBLIC_KEY))


class TestConversation(TestCase):
    # Todo: Add tokens to queries + verify signature

    def setUp(self) -> None:
        self.bob_keys = gen_key_pair()
        self.alice_keys = gen_key_pair()
        self.conversation_keys = gen_key_pair()

    def test_query_validation(self):
        conversation = Conversation.create_from_querier(self.conversation_keys.secret, self.bob_keys.public, query=b'query')

        [token] = create_tokens(1)
        query = conversation.create_query(token)
        assert query.validate(SERVER_PUBLIC_KEY)

        _, pk = AbeParam().generate_new_key_pair()
        assert not query.validate(pk)

        query_invalid_payload = Query(query.public_key, query.token, query.signature, b"invalid")
        assert not query_invalid_payload.validate(SERVER_PUBLIC_KEY)

        query_invalid_public_key = Query(b"deadbeefc0febabe", query.token, query.signature, query.payload)
        assert not query_invalid_public_key.validate(SERVER_PUBLIC_KEY)

    def test_alice_sends_query_conversation(self):
        conversation = Conversation.create_from_querier(self.conversation_keys.secret, self.bob_keys.public, query=b'query')

        [token] = create_tokens(1)
        query = conversation.create_query(token)

        self.assertEqual(conversation.query, b'query')
        self.assertEqual(conversation.nb_recv_messages, 0)
        self.assertEqual(conversation.nb_sent_messages, 1)
        self.assertEqual(self.conversation_keys.public, query.public_key)
        self.assertEqual([b'query'], unpackb(query.payload))
        self.assertIsNotNone(conversation.last_address)
        self.assertEqual(conversation.last_message.type(), MessageType.QUERY)

    def test_bob_receives_query_conversation(self):
        alice_conversation = Conversation.create_from_querier(self.conversation_keys.secret, self.bob_keys.public, query=b'query')
        conversation = Conversation.create_from_recipient(self.bob_keys.secret, self.conversation_keys.public)

        response = conversation.create_response(b'bob query response')
        self.assertEqual(conversation.nb_recv_messages, 1)
        self.assertEqual(conversation.nb_sent_messages, 1)
        self.assertEqual(response.type(), MessageType.RESPONSE)
        self.assertEqual(conversation.last_message.type(), MessageType.RESPONSE)
        self.assertEqual(alice_conversation.last_address.hex(), response.address.hex())
        self.assertIsNotNone(response.payload)

    def test_alice_decrypt_message_from_bob(self):
        alice_conversation = Conversation.create_from_querier(self.conversation_keys.secret, self.bob_keys.public, query=b'query')
        bob_conversation = Conversation.create_from_recipient(self.bob_keys.secret, self.conversation_keys.public)
        response = bob_conversation.create_response(b'response')

        ph = alice_conversation.add_message(response)

        self.assertEqual(alice_conversation.nb_recv_messages, 1)
        self.assertIsNone(alice_conversation.pigeonhole_for_address(ph.address))
        self.assertEqual(alice_conversation.nb_sent_messages, 1)
        self.assertEqual(b'response', alice_conversation.last_message.payload)

    def test_alice_decrypt_message_from_bob_bad_encryption(self):
        alice_conversation = Conversation.create_from_querier(self.conversation_keys.secret, self.bob_keys.public, query=b'query')
        bob_conversation = Conversation.create_from_recipient(self.bob_keys.secret, self.conversation_keys.public)
        response = bob_conversation.create_response(b'response')
        response.payload = pad_message(b"bad message", PH_MESSAGE_LENGTH)

        self.assertIsNone(alice_conversation.add_message(response))
        self.assertEqual(len(alice_conversation._pigeonholes), 1)

    def test_alice_decrypt_message_with_no_pigeonhole_address(self):
        alice_conversation = Conversation.create_from_querier(self.conversation_keys.secret, self.bob_keys.public, query=b'query')

        self.assertIsNone(alice_conversation.add_message(PigeonHoleMessage(b'unknown address', b'payload')))
        self.assertEqual(len(alice_conversation._pigeonholes), 1)

    def test_bob_decrypt_message_from_alice(self):
        alice_conversation = Conversation.create_from_querier(self.conversation_keys.secret, self.bob_keys.public, query=b'query')
        bob_conversation = Conversation.create_from_recipient(self.bob_keys.secret, self.conversation_keys.public)
        message = bob_conversation.create_response(b'response from Bob')
        alice_conversation.add_message(message)

        response = alice_conversation.create_response(b'message from Alice')
        bob_conversation.add_message(response)

        self.assertEqual(bob_conversation.nb_recv_messages, alice_conversation.nb_sent_messages)
        self.assertEqual(bob_conversation.nb_sent_messages, alice_conversation.nb_recv_messages)
        self.assertEqual(b'message from Alice', bob_conversation.last_message.payload)

    def test_is_receiving_address(self):
        alice_conversation = Conversation.create_from_querier(self.conversation_keys.secret, self.bob_keys.public, query=b'query')
        bob_conversation = Conversation.create_from_recipient(self.bob_keys.secret, self.conversation_keys.public)

        response = bob_conversation.create_response(b'response')
        self.assertTrue(alice_conversation.is_receiving(response.address))

        message = alice_conversation.create_response(b'message')
        self.assertTrue(bob_conversation.is_receiving(message.address))

    def test_bob_and_alice_have_a_conversation(self):
        alice_conversation = Conversation.create_from_querier(self.conversation_keys.secret, self.bob_keys.public, query=b'query')
        bob_conversation = Conversation.create_from_recipient(self.bob_keys.secret, self.conversation_keys.public)

        response = bob_conversation.create_response(b'response')
        self.assertTrue(alice_conversation.is_receiving(response.address))
        alice_conversation.add_message(response)

        message = alice_conversation.create_response(b'message1')
        self.assertTrue(bob_conversation.is_receiving(message.address))
        bob_conversation.add_message(message)
        message = alice_conversation.create_response(b'message2')
        self.assertTrue(bob_conversation.is_receiving(message.address))
        bob_conversation.add_message(message)

        message = bob_conversation.create_response(b'bob message1')
        self.assertTrue(alice_conversation.is_receiving(message.address))
        alice_conversation.add_message(message)
        message = bob_conversation.create_response(b'bob message2')
        self.assertTrue(alice_conversation.is_receiving(message.address))
        alice_conversation.add_message(message)


class TestConversationQueryTypes(TestCase):
    def setUp(self) -> None:
        self.bob_keys = gen_key_pair()
        self.alice_keys = gen_key_pair()
        self.conversation_keys = gen_key_pair()

    def test_create_query_cleartext_by_default(self):
        conversation = Conversation.create_from_querier(self.conversation_keys.secret, self.bob_keys.public, query=b'query')
        self.assertEqual(conversation.query_type, QueryType.CLEARTEXT)

        [token] = create_tokens(1)
        query = conversation.create_query(token)
        self.assertEqual(unpackb(query.payload), [conversation.query])

    def test_create_query_dpsi(self):
        conversation = Conversation.create_from_querier(self.conversation_keys.secret, self.bob_keys.public, query=b'query', query_mspsi_secret=MSPSIQuerier.gen_key())
        self.assertEqual(conversation.query_type, QueryType.DPSI)

        [token] = create_tokens(1)
        query = conversation.create_query(token)

        _, query_kwd_encoded = MSPSIQuerier.query([b'query'], conversation.query_mspsi_secret)
        self.assertEqual(query.payload, packb(query_kwd_encoded))

    def test_create_query_dpsi_for_recipient(self):
        conversation = Conversation.create_from_recipient(self.conversation_keys.secret, self.bob_keys.public, query_type=QueryType.DPSI)
        self.assertEqual(conversation.query_type, QueryType.DPSI)

        [token] = create_tokens(1)
        self.assertIsNone(conversation.create_query(token))

    def test_query_response_dpsi(self):
        alice_conversation = Conversation.create_from_querier(self.conversation_keys.secret, self.bob_keys.public, query=b'foo', query_mspsi_secret=MSPSIQuerier.gen_key())
        conversation = Conversation.create_from_recipient(self.bob_keys.secret, self.conversation_keys.public, query_type=QueryType.DPSI)

        [token] = create_tokens(1)
        query = alice_conversation.create_query(token)

        secret, cuckoo_filter = MSPSIDocumentOwner.publish(
            iter(
                (
                    NamedEntity('doc_id', NamedEntityCategory.PERSON, 'foo'),
                    NamedEntity('doc_id', NamedEntityCategory.PERSON, 'bar')
                 )
            ),
            [
                Document('doc_id', datetime.datetime.now())
            ],
            2
        )
        response_payload = conversation.mspsi_encode_query_response(secret, unpackb(query.payload))
        ph_message = conversation.create_response(response_payload)

        ph = alice_conversation.pigeonhole_for_address(ph_message.address)
        ph.decrypt(ph_message.payload)
        kwds_hashes = alice_conversation.mspsi_decode_query_response(ph_message)
        results = MSPSIQuerier.process_reply(kwds_hashes, 1, cuckoo_filter)
        self.assertEqual(len(results), 1)
        self.assertEqual([0], results[0])

        alice_conversation.add_results(packb(results), ph)
        self.assertEqual(alice_conversation.nb_recv_messages, 1)
        self.assertEqual(unpackb(alice_conversation.last_message.payload), results)
        self.assertEqual(alice_conversation.last_message.type(), MessageType.RESPONSE)
        self.assertEqual(alice_conversation.last_message.from_key, self.bob_keys.public)


class TestSerialization(TestCase):
    def test_serialize_deserialize_query(self):
        keys = gen_key_pair()
        query_bytes = Query(keys.public, gen_dummy_abe_signature(), b'signature', b'query').to_bytes()
        self.assertIsInstance(query_bytes, bytes)

        query = Query.from_bytes(query_bytes)
        self.assertIsInstance(query, Query)
        self.assertEqual(b'query', query.payload)
        self.assertEqual(b'signature', query.signature)
        self.assertEqual(keys.public, query.public_key)

    def test_deserialize_wrong_payload(self):
        with self.assertRaises(ValueError):
            Query.from_bytes(packb(["te", "st"]))

    def test_serialize_deserialize_ph_notification(self):
        address = b'deadbeef01234567deadbeef01234567'
        ph_notif = PigeonHoleNotification.from_address(address)
        notification_raw = ph_notif.to_bytes()
        self.assertIsInstance(notification_raw, bytes)

        notification = PigeonHoleNotification.from_bytes(notification_raw)
        self.assertEqual(notification, b"dea".hex())

    def test_deserialize_bad_notification_code(self):
        with self.assertRaises(ValueError):
            PigeonHoleNotification.from_bytes(b'\x02' + b'not a notification payload')

    def test_serialize_ph_message(self):
        address = b'deadbeef01234567deadbeef01234567'
        payload = b'encrypted'
        ph_message = PigeonHoleMessage(address, payload)
        message = ph_message.to_bytes()
        self.assertIsInstance(message, bytes)

        deserialized = PigeonHoleMessage.from_bytes(message)
        self.assertIsInstance(deserialized, PigeonHoleMessage)
        self.assertEqual(deserialized.address, address)
        self.assertEqual(deserialized.payload, payload)
        self.assertEqual(deserialized.type(), MessageType.MESSAGE)

    def test_serialize_ph_response(self):
        address = b'deadbeef01234567deadbeef01234567'
        payload = b'encrypted'
        ph_message = PigeonHoleMessage(address, payload, msg_type=MessageType.RESPONSE)
        message = ph_message.to_bytes()
        self.assertIsInstance(message, bytes)

        deserialized = PigeonHoleMessage.from_bytes(message)
        self.assertIsInstance(deserialized, PigeonHoleMessage)
        self.assertEqual(deserialized.type(), MessageType.RESPONSE)


    def test_serialize_publication_message(self):
        keys = gen_key_pair()
        cuckoo_filter = BCuckooFilter(capacity=1000, error_rate=0.001, bucket_size=6)
        cuckoo_filter.insert(b"deadbeef")
        cuckoo_filter.insert(b"cafebabe")
        publication_msg = PublicationMessage("nym_key", keys.public, cuckoo_filter, 2)
        message = publication_msg.to_bytes()
        self.assertIsInstance(message, bytes)

        deserialized = PublicationMessage.from_bytes(message)
        self.assertIsInstance(deserialized, PublicationMessage)
        self.assertEqual(deserialized.num_documents, 2)
