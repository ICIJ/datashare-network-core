from collections import OrderedDict
from datetime import datetime
from typing import List

from dsnet.crypto import compute_address, compute_sym_key, pad_message, encrypt, decrypt, unpad_message, \
    get_public_key, compute_dhke

# Length of exchanged messages in bytes.
PH_MESSAGE_LENGTH: int = 2048


class PigeonHole:
    def __init__(self, public_key_for_dh: bytes, private_key_for_dh: bytes = None, sender_public_key: bytes = None,
                 message_number: int = 0, dh_key: bytes = None) -> None:
        self.dh_key = compute_dhke(private_key_for_dh, public_key_for_dh) if dh_key is None else dh_key
        self.public_key = sender_public_key if sender_public_key is not None else public_key_for_dh
        self.message_number = message_number

    def encrypt(self, message: str) -> bytes:
        """
        :returns the encrypted message
        :rtype: bytearray
        """
        message_padded = pad_message(message.encode('utf-8'), PH_MESSAGE_LENGTH)
        return encrypt(message_padded, self.sym_key)

    def decrypt(self, ciphered_payload: bytes) -> str:
        padded_payload = decrypt(ciphered_payload, self.sym_key)
        return unpad_message(padded_payload).decode('utf-8')

    @property
    def address(self):
        return compute_address(self.dh_key, self.public_key, self.message_number)

    @property
    def sym_key(self):
        return compute_sym_key(self.dh_key, self.public_key, self.message_number)

    def __repr__(self):
        return 'PigeonHole(address: %s nb: %s)' % (self.address.hex(), self.message_number)


class Query:
    def __init__(self, public_key: bytes, payload: str):
        self.public_key = public_key
        self.payload = payload


class Message:
    def __init__(self, address: bytes, payload: bytes, from_key: bytes, timestamp: datetime = None):
        self.address = address
        self.from_key = from_key
        self.payload = payload
        self.timestamp = timestamp if timestamp is not None else datetime.now()


class Conversation:
    def __init__(self, private_key: bytes, other_public_key: bytes, query: str, querier=False,
                 pigeonholes: List[PigeonHole] = None, messages: List[Message] = None) -> None:
        self.private_key = private_key
        self.public_key = get_public_key(private_key)
        self.other_public_key = other_public_key
        self.query = query
        self.querier = querier
        self.created_at = datetime.now()
        self.nb_sent_messages = 1 if querier else 0
        self.nb_recv_messages = 0 if querier else 1
        self._messages: List[Message] = list() if messages is None else messages
        self._pigeonholes: OrderedDict[bytes, PigeonHole] = OrderedDict()
        if querier and messages is None:
            self._create_and_save_next_pigeonhole()
        if pigeonholes is not None:
            for ph in pigeonholes:
                self._pigeonholes[ph.address] = ph

    def get_query(self) -> Query:
        """
        Returns a new query object
        """
        return Query(self.public_key, self.query)

    def create_response(self, payload: str) -> Message:
        """
        Create a response to query
        """
        ph = self._create_recipient_pigeonhole()
        self.nb_sent_messages += 1
        self._create_and_save_next_pigeonhole()
        return Message(ph.address, ph.encrypt(payload), self.public_key)

    def add_message(self, message: Message) -> None:
        """
        Add a message to the conversation
        """
        self.nb_recv_messages += 1
        ph = self._pigeonholes[message.address]
        cleartext = ph.decrypt(message.payload)
        self._messages.append(Message(message.address, cleartext.encode('utf-8'), from_key=message.from_key))
        self._create_and_save_next_pigeonhole()

    @property
    def last_address(self) -> bytes:
        return self._pigeonholes[next(reversed(self._pigeonholes))].address

    @property
    def last_message(self) -> Message:
        return self._messages[-1]

    def is_receiving(self, address: bytes) -> bool:
        return address in self._pigeonholes

    def pigeonhole_for_address(self, address: bytes) -> PigeonHole:
        return self._pigeonholes.get(address)

    def _create_and_save_next_pigeonhole(self) -> PigeonHole:
        ph = self._create_pigeonhole()
        self._pigeonholes[ph.address] = ph
        return ph

    def _create_recipient_pigeonhole(self):
        return self._create_pigeonhole(for_sending=True)

    def _create_pigeonhole(self, for_sending=False) -> PigeonHole:
        nb_messages = self.nb_sent_messages if for_sending else self.nb_recv_messages
        sender_public_key = self.public_key if self.querier else None
        return PigeonHole(self.other_public_key, self.private_key, sender_public_key, nb_messages)

    def __str__(self) -> str:
        return self.__repr__()

    def __repr__(self) -> str:
        return 'Conversation(public_key: %s sent: %d recv: %d)' % \
               (self.public_key.hex(), self.nb_sent_messages, self.nb_recv_messages)
