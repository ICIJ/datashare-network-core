from collections import OrderedDict
from typing import List

from dsnet.crypto import compute_address, compute_sym_key, pad_message, encrypt, decrypt, unpad_message, get_public_key, \
    compute_dhke


# Length of exchanged messages in bytes.
PH_MESSAGE_LENGTH: int = 2048


class PigeonHole:
    def __init__(self, dh_key: bytes, sender_public_key: bytes, number: int = 0) -> None:
        self.address = compute_address(dh_key, sender_public_key, number)
        self.sym_key = compute_sym_key(dh_key, sender_public_key, number)
        self.number = number

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

    def __repr__(self):
        return 'PigeonHole(address: %s nb: %s)' % (self.address.hex(), self.number)


class Query:
    def __init__(self, public_key: bytes, payload: str):
        self.public_key = public_key
        self.payload = payload


class Message:
    def __init__(self, address: bytes, payload: bytes):
        self.address = address
        self.payload = payload


class Conversation:
    def __init__(self, private_key: bytes, other_public_key: bytes, querier=False) -> None:
        self.private_key = private_key
        self.public_key = get_public_key(private_key)
        self.other_public_key = other_public_key
        self.querier = querier
        self.nb_sent_messages = 0
        self.nb_recv_messages = 0
        self.dh_key = compute_dhke(private_key, other_public_key)
        self._pigeon_holes: OrderedDict[bytes, PigeonHole] = OrderedDict()
        self._messages: List[str] = list()

    def create_query(self, payload: str) -> Query:
        """
        Creates a new query
        """
        self._create_and_save_next_pigeon_hole()
        self.nb_sent_messages += 1
        return Query(self.public_key, payload)

    def create_response(self, payload: str) -> Message:
        """
        Create a response to query
        """
        ph = self._create_recipient_pigeon_hole()
        self.nb_sent_messages += 1
        self._create_and_save_next_pigeon_hole()
        return Message(ph.address, ph.encrypt(payload))

    def add_query(self, query: Query) -> None:
        self._messages.append(query.payload)
        self.nb_recv_messages += 1

    def add_message(self, message: Message) -> None:
        """
        Add a message to the conversation
        """
        self.nb_recv_messages += 1
        ph = self._pigeon_holes[message.address]
        cleartext = ph.decrypt(message.payload)
        self._messages.append(cleartext)
        self._create_and_save_next_pigeon_hole()

    @property
    def last_address(self) -> bytes:
        return self._pigeon_holes[next(reversed(self._pigeon_holes))].address

    @property
    def last_message(self) -> str:
        return self._messages[-1]

    def _create_and_save_next_pigeon_hole(self) -> PigeonHole:
        ph = self._create_pigeon_hole()
        self._pigeon_holes[ph.address] = ph
        return ph

    def _create_recipient_pigeon_hole(self):
        return self._create_pigeon_hole(for_sending=True)

    def _create_pigeon_hole(self, for_sending=False) -> PigeonHole:
        nb_messages = self.nb_sent_messages if for_sending else self.nb_recv_messages
        return PigeonHole(self.dh_key, self.public_key, nb_messages) if self.querier \
            else PigeonHole(self.dh_key, self.other_public_key, nb_messages)

    def is_receiving(self, address: bytes) -> bool:
        return address in self._pigeon_holes

    def pigeon_hole_for_address(self, address: bytes) -> PigeonHole:
        return self._pigeon_holes.get(address)

    def __str__(self) -> str:
        return self.__repr__()

    def __repr__(self) -> str:
        return 'Conversation(dhk: %s sent: %d recv: %d)' % \
               (self.dh_key.hex(), self.nb_sent_messages, self.nb_recv_messages)

