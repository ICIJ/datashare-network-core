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

    def __str__(self) -> str:
        return 'PigeonHole(address: %s nb: %s)' % (self.address.hex(), self.number)


class Conversation:
    def __init__(self, private_key: bytes, other_public_key: bytes) -> None:
        self.private_key = private_key
        self.public_key = get_public_key(private_key)
        self.other_public_key = other_public_key
        self.nb_sent_messages = 0
        self.nb_recv_messages = 0
        self.dh_key = compute_dhke(private_key, other_public_key)
        self._receiving_pigeon_holes = list()

    async def create_next_receiving_pigeon_hole(self) -> PigeonHole:
        hole = self._create_pigeon_hole()
        self._receiving_pigeon_holes.append(hole)
        return hole

    def create_sending_pigeon_hole(self) -> PigeonHole:
        return self._create_pigeon_hole(for_sending=True)

    def _create_pigeon_hole(self, for_sending=False) -> PigeonHole:
        if for_sending:
            pigeon_hole = PigeonHole(self.dh_key, self.public_key, self.nb_sent_messages)
            self.nb_sent_messages += 1
        else:
            pigeon_hole = PigeonHole(self.dh_key, self.other_public_key, self.nb_recv_messages)
            self.nb_recv_messages += 1

        return pigeon_hole

    def is_receiving(self, address: bytes) -> bool:
        return address in [ph.address for ph in self._receiving_pigeon_holes]

    def pigeon_hole_for_address(self, address: bytes) -> PigeonHole:
        phs = [ph for ph in self._receiving_pigeon_holes if ph.address == address]
        if len(phs) > 1: print('WARN: several pigeon holes %s for address %s' % (phs, address.hex()))
        return phs[0]

    def __str__(self) -> str:
        return self.__repr__()

    def __repr__(self) -> str:
        return 'Conversation(dhk: %s sent: %d recv: %d)' % \
               (self.dh_key.hex(), self.nb_sent_messages, self.nb_recv_messages)

