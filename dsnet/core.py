from __future__ import annotations

from collections import OrderedDict
from datetime import datetime
from typing import List, Optional

from dsnet.crypto import compute_address, compute_sym_key, pad_message, encrypt, decrypt, unpad_message, \
    get_public_key, compute_dhke

from dsnet.message import PigeonHoleMessage, Query

# Length of exchanged messages in bytes.
PH_MESSAGE_LENGTH: int = 2048


class PigeonHole:
    def __init__(self, public_key_for_dh: bytes, private_key_for_dh: bytes = None, sender_public_key: bytes = None,
                 message_number: int = 0, dh_key: bytes = None) -> None:
        self.dh_key = compute_dhke(private_key_for_dh, public_key_for_dh) if dh_key is None else dh_key
        self.public_key = sender_public_key if sender_public_key is not None else public_key_for_dh
        self.message_number = message_number

    def encrypt(self, message: bytes) -> bytes:
        """
        :returns the encrypted message
        :rtype: bytearray
        """
        message_padded = pad_message(message, PH_MESSAGE_LENGTH)
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


class Conversation:
    def __init__(self,
                 private_key: bytes,
                 other_public_key: bytes,
                 nb_sent_messages: int,
                 nb_recv_messages: int,
                 querier: bool = False,
                 created_at: Optional[datetime] = None,
                 query: Optional[bytes] = None,
                 pigeonholes: List[PigeonHole] = None,
                 messages: List[PigeonHoleMessage] = None
                 ) -> None:
        self.private_key = private_key
        self.public_key = get_public_key(private_key)
        self.other_public_key = other_public_key
        self.query = query
        self.querier = querier
        self.created_at = datetime.now() if created_at is None else created_at
        self.nb_sent_messages = nb_sent_messages
        self.nb_recv_messages = nb_recv_messages
        self._messages: List[PigeonHoleMessage] = list() if messages is None else messages
        self._pigeonholes: OrderedDict[bytes, PigeonHole] = OrderedDict()

        if pigeonholes is not None:
            for ph in pigeonholes:
                self._pigeonholes[ph.address] = ph

    @classmethod
    def create_from_querier(
            cls,
            private_key: bytes,
            other_public_key: bytes,
            query: bytes,
            pigeonholes: List[PigeonHole] = None,
            messages: List[PigeonHoleMessage] = None
    ) -> Conversation:

        conversation = cls(
            private_key,
            other_public_key,
            nb_sent_messages=1,
            nb_recv_messages=0,
            querier=True,
            query=query,
            pigeonholes=pigeonholes,
            messages=messages
        )

        if messages is None:
            conversation._create_and_save_next_pigeonhole()

        return conversation

    @classmethod
    def create_from_recipient(
            cls,
            private_key: bytes,
            other_public_key: bytes,
            pigeonholes: List[PigeonHole] = None,
            messages: List[PigeonHoleMessage] = None
    ) -> Conversation:

        return cls(
            private_key,
            other_public_key,
            nb_sent_messages=0,
            nb_recv_messages=1,
            querier=False,
            query=None,
            pigeonholes=pigeonholes,
            messages=messages
        )

    def get_query(self) -> Query:
        """
        Returns a new query object
        """
        return Query(self.public_key, self.query) if self.query else None

    def create_response(self, payload: bytes) -> PigeonHoleMessage:
        """
        Create a response to query
        """
        ph = self._create_recipient_pigeonhole()
        self.nb_sent_messages += 1
        self._create_and_save_next_pigeonhole()
        return PigeonHoleMessage(ph.address, ph.encrypt(payload), self.public_key)

    def add_message(self, message: PigeonHoleMessage) -> None:
        """
        Add a message to the conversation
        """
        self.nb_recv_messages += 1
        ph = self._pigeonholes[message.address]
        cleartext = ph.decrypt(message.payload)
        self._messages.append(PigeonHoleMessage(message.address, cleartext.encode('utf-8'), from_key=message.from_key))
        self._create_and_save_next_pigeonhole()

    @property
    def last_address(self) -> bytes:
        return self._pigeonholes[next(reversed(self._pigeonholes))].address

    @property
    def last_message(self) -> PigeonHoleMessage:
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
