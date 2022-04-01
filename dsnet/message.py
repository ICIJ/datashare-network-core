from __future__ import annotations

import abc
from datetime import datetime
from enum import IntEnum
from typing import Optional

from cryptography.exceptions import InvalidSignature
from sscred import AbeSignature, packb, unpackb, AbePublicKey
from sscred.pack import add_msgpack_support

from dsnet.token import verify

class Message(metaclass=abc.ABCMeta):
    """
    meta class for binary data sent over the wire
    """
    @abc.abstractmethod
    def to_bytes(self) -> bytes:
        """
        :return: the binary payload of the message
        """

    @abc.abstractmethod
    def type(self) -> MessageType:
        """
        getter for the message type
        :return: type of the message
        """


class MessageType(IntEnum):
    QUERY = 1
    RESPONSE = 2
    MESSAGE = 3
    NOTIFICATION = 4

    @classmethod
    def dumps(cls, msg: Message) -> bytes:
        return msg.to_bytes()

    @classmethod
    def loads(cls, payload: bytes) -> Message:
        obj = unpackb(payload)
        if isinstance(obj, PigeonHoleMessagePayload):
            return PigeonHoleMessage(obj.address, obj.payload)
        if isinstance(obj, Message):
            return obj
        raise ValueError(f"unknown message type {payload[0]}")


class Query(Message):
    MSGPACK_ID = 100

    def __init__(self, public_key: bytes, token: AbeSignature, signature: bytes, payload: bytes):
        self.public_key = public_key
        self.signature = signature
        self.token = token
        self.payload = payload

    def validate(self, token_server_public_key: AbePublicKey) -> bool:
        """
        Validates the query.

        :param server_public_key: public key of the token server
        :return: True if the query is valid, False otherwise
        """
        try:
            verify(self.public_key + self.payload, self.signature, self.token.message)
        except InvalidSignature:
            return False

        return token_server_public_key.verify_signature(self.token)


    def type(self) -> MessageType:
        return MessageType.QUERY

    def to_bytes(self) -> bytes:
        return packb(self)

    @classmethod
    def from_bytes(cls, payload: bytes):
        res = unpackb(payload)
        if not isinstance(res, Query):
            raise ValueError("Payload is not a query")
        return res


add_msgpack_support(Query, Query.MSGPACK_ID, add_cls_methods=False)


class PigeonHoleMessage(Message):
    def __init__(self, address: Optional[bytes], payload: Optional[bytes], from_key: Optional[bytes] = None, timestamp: Optional[datetime] = None, conversation_id: Optional[int] = None):
        self.address = address
        self.payload = payload
        self.from_key = from_key
        self.timestamp = timestamp if timestamp is not None else datetime.now()
        self.conversation_id = conversation_id

    def type(self) -> MessageType:
        return MessageType.MESSAGE

    def to_bytes(self) -> bytes:
        message = PigeonHoleMessagePayload(self.address, self.payload)
        return packb(message)

    @classmethod
    def from_bytes(cls, payload) -> PigeonHoleMessage:
        ph_payload = unpackb(payload)
        return cls(ph_payload.address, ph_payload.payload)


class PigeonHoleMessagePayload:
    MSGPACK_ID = 101

    def __init__(self, address: bytes, payload: bytes):
        self.address = address
        self.payload = payload

    def to_bytes(self) -> bytes:
        return packb(self)


add_msgpack_support(PigeonHoleMessagePayload, PigeonHoleMessagePayload.MSGPACK_ID, add_cls_methods=False)


class PigeonHoleNotification(Message):
    MSGPACK_ID = 102
    ADR_LENGTH = 3

    def __init__(self, adr_hex: str):
        self.adr_hex = adr_hex

    def type(self) -> MessageType:
        return MessageType.NOTIFICATION

    def to_bytes(self) -> bytes:
        return packb(self)

    @classmethod
    def from_bytes(cls, payload: bytes):
        res = unpackb(payload)
        if not isinstance(res, PigeonHoleNotification):
            raise ValueError("Payload is not a notification")
        return res.adr_hex

    @classmethod
    def from_address(cls, address: bytes):
        return cls(address[0:PigeonHoleNotification.ADR_LENGTH].hex())


add_msgpack_support(PigeonHoleNotification, PigeonHoleNotification.MSGPACK_ID, add_cls_methods=False)

