"""
Multi set PSI
"""

from hashlib import blake2b
from typing import Generator, List, Tuple

from petlib.bn import Bn
from petlib.ec import EcGroup, EcPt

from cuckoo.filter import BCuckooFilter


CUCKOO_FILTER_CAPACITY_MIN = 1000
CUCKOO_FILTER_CAPACITY_FRACTION = 0.3
CUCKOO_FILTER_BUCKET_SIZE = 6
CUCKOO_FILTER_ERROR_RATE = 0.0001
CUCKOO_FILTER_MAX_KICKS = 500

DOC_ID_SIZE = 4
MSPSI_EC_NID = 415
MSPSI_EC_CURVE = EcGroup(MSPSI_EC_NID)


def kwd_encode(doc_id: bytes, kwd:bytes) -> bytes:
    """
    Hash an encrypted keyword and its doc id with a cryptographically secure hash function.
    :param doc_id: id of the document
    :param kwd: an encrypted keyword in the document
    :return: a cryptographically secure hash as a binary string
    """
    return blake2b(doc_id + kwd).digest()


class MSPSIQuerier:
    """
    Query side of the MSPSI protocole
    """

    @staticmethod
    def query(kwds: List[bytes]) -> Tuple[Bn, List[bytes]]:
        """
        Generate a query from the keywords.
        :param kwds: Set of keywords to be queried
        :return: A secret to generate the query and the query as a list of points on the EC.
        """

        secret = MSPSI_EC_CURVE.order().random()

        query_enc = list()

        for kwd in kwds:
            kwd_pt = MSPSI_EC_CURVE.hash_to_point(kwd)
            kwd_enc = secret * kwd_pt
            kwd_enc_bytes: bytes = kwd_enc.export()
            query_enc.append(kwd_enc_bytes)

        return (secret, query_enc)


    @staticmethod
    def compute_cardinalities(secret: Bn, reply: List[bytes], documents_number: int, published_hashes: BCuckooFilter) -> List[int]:
        """
        Compute the cardinalyty of the intersection of sets between the reply to a query
        and the list of lists of points published by the server.
        :param secret: secret with which the query was encrypted
        :param reply: reply from the server
        :param documents_number: the number of documents (to generate their IDs)
        :param published_hashes: list of keywords hashes published by the server as a cuckoo filter
        :return: list of cardinalities for the intersection between the reply and each published list of points.
        """

        secret_inv = secret.mod_inverse(MSPSI_EC_CURVE.order())
        cardinalities = []

        # For optimisation the following assumptions are made
        # - all keywords in the query are different.
        # - all keywords in the document are different.
        kwds_dec = list()

        for kwd_h in reply:
            kwd_pt = EcPt.from_binary(kwd_h, MSPSI_EC_CURVE)
            kwd_pt_dec = secret_inv * kwd_pt
            kwd_bytes = kwd_pt_dec.export()
            kwds_dec.append(kwd_bytes)

        for doc_id in range(documents_number):
            n_matches = 0
            encoded_doc_id = doc_id.to_bytes(DOC_ID_SIZE, byteorder="big")
            for kwd_dec in kwds_dec:
                kwd_docid_bytes = kwd_encode(encoded_doc_id, kwd_dec)
                if published_hashes.contains(kwd_docid_bytes):
                    n_matches += 1
            cardinalities.append(n_matches)

        return cardinalities



class MSPSIDocumentOwner:
    """
    Document owner side of the MSPSI protocole
    """

    @staticmethod
    def published_len(published: BCuckooFilter) -> int:
        """
        Compute the size of a given published data.
        :param published: list of published hashes in a cuckoo filter
        """
        published_data = published
        capacity = published_data.capacity
        bucket_size = published_data.bucket_size
        return capacity * bucket_size


    @staticmethod
    def publish(docs: Generator[List[bytes], None, None], capacity: int) -> Tuple[Bn, BCuckooFilter]:
        """
        Generate a list of lists of points on the EC corresponding to a document's keywords.
        :param docs: generator of lists of keywords for each document
        :param capacity: expected capacity of the cuckoo filter
        :return: a secret with wich the keywords were encrypted and a cuckoo filter containing the encrypted keywords.
        """

        cuckoo_capacity = max(CUCKOO_FILTER_CAPACITY_MIN, capacity)

        secret = MSPSI_EC_CURVE.order().random()

        published_hashes = BCuckooFilter(
            capacity=cuckoo_capacity,
            error_rate=CUCKOO_FILTER_ERROR_RATE,
            bucket_size=CUCKOO_FILTER_BUCKET_SIZE,
            max_kicks=CUCKOO_FILTER_MAX_KICKS
        )

        for doc_id, kwds in enumerate(docs):
            encoded_doc_id = doc_id.to_bytes(DOC_ID_SIZE, byteorder="big")
            for kwd in kwds:
                kwd_pt = MSPSI_EC_CURVE.hash_to_point(kwd)
                kwd_enc = secret * kwd_pt # type: Bn
                kwd_enc_bytes = kwd_enc.export()
                kwd_docid_bytes = kwd_encode(encoded_doc_id, kwd_enc_bytes)
                published_hashes.insert(kwd_docid_bytes)

        return (secret, published_hashes)


    @staticmethod
    def reply(secret: Bn, query: List[bytes]) -> List[Bn]:
        """
        Compute a reply to a query.
        :param secret: secret with which the keywords were encrypted during the publication
        :param query: query to be answered
        :return: reply to the query
        """

        reply = list()

        for kwd_h in query:
            kwd_pt = EcPt.from_binary(kwd_h, MSPSI_EC_CURVE)
            kwd_enc = secret * kwd_pt # type: Bn
            kwd_enc_bytes = kwd_enc.export()
            reply.append(kwd_enc_bytes)

        return reply
