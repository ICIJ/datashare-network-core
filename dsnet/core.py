from __future__ import annotations

from collections import OrderedDict
from datetime import datetime
from typing import List, Optional

from cryptography.exceptions import InvalidTag

from dsnet.crypto import compute_address, compute_sym_key, pad_message, encrypt, decrypt, unpad_message, \
    get_public_key, compute_dhke
from dsnet.logger import logger

from dsnet.message import PigeonHoleMessage, Query

# Length of exchanged messages in bytes.
PH_MESSAGE_LENGTH: int = 2048


class PigeonHole:
    def __init__(self, public_key_for_dh: bytes = None, secret_key_for_dh: bytes = None, key_for_hash: bytes = None,
                 message_number: int = 0, dh_key: bytes = None, conversation_id: Optional[int] = None) -> None:
        self.dh_key = compute_dhke(secret_key_for_dh, public_key_for_dh) if dh_key is None else dh_key
        self.key_for_hash = key_for_hash
        self.message_number = message_number
        self.conversation_id = conversation_id

    @classmethod
    def create_querier_sending_ph(cls, pkx: bytes, skq: bytes, number_messages_sent: int) -> PigeonHole:
        """
        addr := H("addr" || dh(skq, pkx) || pkq || #msg)
        key_sym := H("key" || dh(skq, pkx) || pkq || #msg)
        :param pkx: public key recipient (potential respondent)
        :param skq: secret key query
        :param number_messages_sent:
        :return: PigeonHole
        """
        return cls(pkx, skq, get_public_key(skq), number_messages_sent)

    @classmethod
    def create_querier_receiving_ph(cls, pkx: bytes, skq: bytes, number_messages_received: int) -> PigeonHole:
        """
        addr := H("addr" || dh(skq, pkx) || pkx || #msg)
        :param pkx: public key recipient (potential respondent)
        :param skq: secret key query
        :param number_messages_received:
        :return: PigeonHole
        """
        return cls(pkx, skq, pkx, number_messages_received)

    @classmethod
    def create_respondent_sending_ph(cls, pkq: bytes, skx: bytes, number_messages_sent: int) -> PigeonHole:
        """
        addr := H("addr" || dh(skx, pkq) || pkx || #msg)
        :param pkq: public key query
        :param skx: respondent secret key
        :param number_messages_sent:
        :return: PigeonHole
        """
        return cls(pkq, skx, get_public_key(skx), number_messages_sent)

    @classmethod
    def create_respondent_receiving_ph(cls, pkq: bytes, skx: bytes, number_messages_received: int) -> PigeonHole:
        """
        addr := H("addr" || dh(skx, pkq) || pkq || #msg)
        :param pkq: public key query
        :param skx: respondent secret key
        :param number_messages_received:
        :return: PigeonHole
        """
        return cls(pkq, skx, pkq, number_messages_received)

    def encrypt(self, message: bytes) -> bytes:
        """
        :returns the encrypted message
        :rtype: bytearray
        """
        message_padded = pad_message(message, PH_MESSAGE_LENGTH)
        return encrypt(message_padded, self.sym_key)

    def decrypt(self, ciphered_payload: bytes) -> bytes:
        padded_payload = decrypt(ciphered_payload, self.sym_key)
        return unpad_message(padded_payload)

    @property
    def address(self):
        return compute_address(self.dh_key, self.key_for_hash, self.message_number)

    @property
    def sym_key(self):
        return compute_sym_key(self.dh_key, self.key_for_hash, self.message_number)

    def __repr__(self):
        return 'PigeonHole(address: %s nb: %s)' % (self.address.hex(), self.message_number)


class Conversation:
    def __init__(self,
                 secret_key: bytes,
                 other_public_key: bytes,
                 querier: bool = False,
                 created_at: Optional[datetime] = None,
                 query: Optional[bytes] = None,
                 pigeonholes: List[PigeonHole] = None,
                 messages: List[PigeonHoleMessage] = None,
                 id: Optional[int] = None
                 ) -> None:
        self.secret_key = secret_key
        self.public_key = get_public_key(secret_key)
        self.other_public_key = other_public_key
        self.query = query
        self.querier = querier
        self.created_at = datetime.now() if created_at is None else created_at
        self._messages: List[PigeonHoleMessage] = list() if messages is None else messages
        self._pigeonholes: OrderedDict[bytes, PigeonHole] = OrderedDict()
        self.id = id

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
            querier=True,
            query=query,
            pigeonholes=pigeonholes,
            messages=messages
        )

        if messages is None:
            conversation._messages.append(PigeonHoleMessage(None, query, from_key=conversation.public_key))
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

        conversation = cls(
            private_key,
            other_public_key,
            querier=False,
            query=None,
            pigeonholes=pigeonholes,
            messages=messages
        )

        if messages is None:
            conversation._messages.append(PigeonHoleMessage(None, None, from_key=conversation.other_public_key))
        return conversation

    def get_query(self) -> Query:
        """
        Returns a new query object
        """
        return Query(self.public_key, self.query) if self.query else None

    def create_response(self, payload: bytes) -> PigeonHoleMessage:
        """
        Create a response to query
        """
        tmp_recipient_ph = self._create_recipient_pigeonhole()
        message = PigeonHoleMessage(tmp_recipient_ph.address, tmp_recipient_ph.encrypt(payload), from_key=self.public_key)
        self._messages.append(PigeonHoleMessage(message.address, payload, from_key=self.public_key))
        self._create_and_save_next_pigeonhole()
        return message

    def add_message(self, message: PigeonHoleMessage) -> Optional[PigeonHole]:
        """
        Add a message to the conversation
        """
        ph = self._pigeonholes.get(message.address)
        if ph is not None:
            try:
                cleartext = ph.decrypt(message.payload)
                del self._pigeonholes[message.address]
                self._messages.append(PigeonHoleMessage(message.address, cleartext, from_key=message.from_key))
                self._create_and_save_next_pigeonhole()
                return ph
            except InvalidTag:
                logger.warning(f'failed to decrypt message at address {message.address.hex()}')

    @property
    def nb_sent_messages(self) -> int:
        return sum(1 for _ in filter(lambda m: m.from_key == self.public_key, self._messages))

    @property
    def nb_recv_messages(self) -> int:
        return sum(1 for _ in filter(lambda m: m.from_key != self.public_key, self._messages))

    @property
    def last_address(self) -> Optional[bytes]:
        return self._pigeonholes[next(reversed(self._pigeonholes))].address if self._pigeonholes else None

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
        if self.querier:
            return PigeonHole.create_querier_sending_ph(self.other_public_key, self.secret_key, self.nb_sent_messages)
        else:
            return PigeonHole.create_respondent_sending_ph(self.other_public_key, self.secret_key, self.nb_sent_messages)

    def _create_pigeonhole(self) -> PigeonHole:
        if self.querier:
            return PigeonHole.create_querier_receiving_ph(self.other_public_key, self.secret_key, self.nb_recv_messages)
        else:
            return PigeonHole.create_respondent_receiving_ph(self.other_public_key, self.secret_key, self.nb_recv_messages)

    def __str__(self) -> str:
        return self.__repr__()

    def __repr__(self) -> str:
        return 'Conversation(public_key: %s sent: %d recv: %d)' % \
               (self.public_key.hex(), self.nb_sent_messages, self.nb_recv_messages)
