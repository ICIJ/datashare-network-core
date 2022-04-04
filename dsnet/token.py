from __future__ import annotations
from typing import NamedTuple, List, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives._serialization import PrivateFormat, NoEncryption, Encoding
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from sscred import AbeSignature, SignerCommitMessage, BlindedChallengeMessage, SignerResponseMessage, AbePublicKey, \
    AbeUser, UserBlindedChallengeInternalState, AbeSigner, SignerCommitmentInternalState


class AbeToken(NamedTuple):
    secret_key: Ed25519PrivateKey
    token: AbeSignature

    def sign(self, message: bytes) -> bytes:
        """
        Sign a message with a psecret key.

        :param message: the message to sign
        :return: signature
        """
        return self.secret_key.sign(message)

    def __eq__(self, other: AbeToken) -> bool:
        return self.token == other.token and secret_key_binary(self.secret_key) == secret_key_binary(other.secret_key)


def secret_key_binary(skey: Ed25519PrivateKey) -> bytes:
    return skey.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


def generate_commitments(
        signer: AbeSigner,
        nb: int
) -> Tuple[List[SignerCommitMessage], List[SignerCommitmentInternalState]]:
    commitments = list()
    commitments_internal = list()
    for _ in range(nb):
        commit, commit_internal = signer.commit()
        commitments.append(commit)
        commitments_internal.append(commit_internal)
    return commitments, commitments_internal


def generate_challenges(
        server_public_key: AbePublicKey,
        commitments: List[SignerCommitMessage]
) -> Tuple[List[BlindedChallengeMessage], List[UserBlindedChallengeInternalState], List[Ed25519PrivateKey]]:
    abe_user = AbeUser(server_public_key)
    challenges: List[BlindedChallengeMessage] = []
    challenges_internal: List[UserBlindedChallengeInternalState] = []
    token_secret_keys: List[Ed25519PrivateKey] = []
    # Compute challenges to send back to the server
    for commitment in commitments:
        ephemeral_secret_key = Ed25519PrivateKey.generate()
        ephemeral_public_key_raw = ephemeral_secret_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        token_secret_keys.append(ephemeral_secret_key)

        challenge, internal = abe_user.compute_blind_challenge(commitment, ephemeral_public_key_raw)
        challenges.append(challenge)
        challenges_internal.append(internal)
    return challenges, challenges_internal, token_secret_keys


def generate_pretokens(signer: AbeSigner,
                       challenges: List[BlindedChallengeMessage],
                       coms_internal: List[SignerCommitmentInternalState]) -> List[SignerResponseMessage]:
    pre_tokens = []
    for challenge, internal in zip(challenges, coms_internal):
        pre_tokens.append(signer.respond(challenge, internal))
    return pre_tokens


def generate_tokens(server_public_key: AbePublicKey,
                    challenges: List[UserBlindedChallengeInternalState],
                    secret_keys: List[Ed25519PrivateKey],
                    pretokens: List[SignerResponseMessage]) -> List[AbeToken]:
    abe_user = AbeUser(server_public_key)
    tokens = list()
    for pretoken, internal, secret_key in zip(pretokens, challenges, secret_keys):
        token = abe_user.compute_signature(pretoken, internal)
        tokens.append(AbeToken(secret_key, token))
    return tokens


def verify(message: bytes, signature: bytes, public_key: bytes) -> None:
    """
    Verify a signature.

    :param message:
    :param signature:
    :param public_key:
    :raises cryptography.exceptions.InvalidSignature: the signature is invalid
    """
    public_key_obj = Ed25519PublicKey.from_public_bytes(public_key)
    public_key_obj.verify(signature, message)
