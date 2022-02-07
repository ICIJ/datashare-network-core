from __future__ import annotations

import abc
from datetime import datetime
from enum import IntEnum
from typing import Optional

from dsnet.crypto import ENCRYPTION_KEY_LENGTH, ADDRESS_LENGTH


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
        if payload[0] == MessageType.NOTIFICATION:
            return PigeonHoleNotification.from_bytes(payload)
        if payload[0] == MessageType.QUERY:
            return Query.from_bytes(payload)
        if payload[0] == MessageType.MESSAGE:
            return PigeonHoleMessage.from_bytes(payload)
        raise ValueError(f"unknown message type {payload[0]}")


class Query(Message):
    def __init__(self, public_key: bytes, payload: bytes):
        self.public_key = public_key
        self.payload = payload

    def type(self) -> MessageType:
        return MessageType.QUERY

    def to_bytes(self):
        return self.type().to_bytes(1, byteorder='big') + self.public_key + self.payload

    @classmethod
    def from_bytes(cls, payload: bytes):
        if payload[0] != MessageType.QUERY:
            raise ValueError(f'{payload[0]} is not a query metadata code')
        return cls(payload[1:ENCRYPTION_KEY_LENGTH + 1], payload[ENCRYPTION_KEY_LENGTH + 1:])


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
        return self.type().to_bytes(1, byteorder='big') + self.address + self.payload

    @classmethod
    def from_bytes(cls, payload) -> PigeonHoleMessage:
        if payload[0] != MessageType.MESSAGE:
            raise ValueError(f'{payload[0]} is not a message metadata code')
        return cls(payload[1:ADDRESS_LENGTH + 1], payload[ADDRESS_LENGTH + 1:])


class PigeonHoleNotification(Message):
    ADR_LENGTH = 3

    def __init__(self, adr_hex: str):
        self.adr_hex = adr_hex

    def type(self) -> MessageType:
        return MessageType.NOTIFICATION

    def to_bytes(self) -> bytes:
        return self.type().to_bytes(1, 'big') + bytes.fromhex(self.adr_hex)

    @classmethod
    def from_bytes(cls, payload: bytes):
        if payload[0] != MessageType.NOTIFICATION:
            raise ValueError(f'{payload[0]} is not a notification metadata code')
        return cls(payload[1:].hex())

    @classmethod
    def from_address(cls, address: bytes):
        return cls(address[0:PigeonHoleNotification.ADR_LENGTH].hex())

