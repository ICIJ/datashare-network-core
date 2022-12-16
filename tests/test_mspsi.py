import random
import string
import unittest
from datetime import datetime, timedelta
from uuid import uuid4

from dsnet.mspsi import Document, MSPSIQuerier, MSPSIDocumentOwner, NamedEntity, NamedEntityCategory


class TestMSPSI(unittest.TestCase):
    docs = [
        Document("beef", datetime.utcnow() - timedelta(seconds=10)),
        Document("feed", datetime.utcnow() - timedelta(seconds=8)),
        Document("coffee", datetime.utcnow() - timedelta(seconds=6)),
    ]
    nes = [
        NamedEntity('beef', NamedEntityCategory.PERSON, 'foo'),
        NamedEntity('beef', NamedEntityCategory.PERSON, 'bar'),
        NamedEntity('beef', NamedEntityCategory.PERSON, 'tux'),
        NamedEntity('feed', NamedEntityCategory.PERSON, 'baz'),
        NamedEntity('feed', NamedEntityCategory.PERSON, 'foo'),
        NamedEntity('coffee', NamedEntityCategory.PERSON, 'asdf'),
    ]

    def test_two_one_zero_matching(self):
        (secret_server, published) = MSPSIDocumentOwner.publish((kwds for kwds in self.nes), self.docs, 4)

        (secret_client, query) = MSPSIQuerier.query([b'foo', b'tux'])
        cards = self._encode_decode(published, query, secret_client, secret_server)

        self.assertEqual(cards, [[0, 1], [0], []])

    def test_one_one_zero_matching(self):
        (secret_server, published) = MSPSIDocumentOwner.publish((kwds for kwds in self.nes), self.docs, 4)

        (secret_client, query) = MSPSIQuerier.query([b'bar', b'baz'])
        cards = self._encode_decode(published, query, secret_client, secret_server)

        self.assertEqual(cards, [[0], [1], []])

    def test_zero_zero_one(self):
        (secret_server, published) = MSPSIDocumentOwner.publish((kwds for kwds in self.nes), self.docs, 4)

        (secret_client, query) = MSPSIQuerier.query([b'asdf', b'ghjk'])
        cards = self._encode_decode(published, query, secret_client, secret_server)

        self.assertEqual(cards, [[], [], [0]])

    @staticmethod
    def _encode_decode(published, query, secret_client, secret_server):
        reply = MSPSIDocumentOwner.reply(secret_server, query)
        decoded_kwds = MSPSIQuerier.decode_reply(secret_client, reply)
        cards = MSPSIQuerier.process_reply(decoded_kwds, 3, published)
        return cards

    @unittest.skip("Benchmark to measure occurrences of false negatives and false positives")
    def test_false_positives(self):
        # Random data generation with keywords known to be inside the corpus
        random.seed(0)

        # sets of documents are generated.
        kwds_in_doc_and_in_query = set([b''.join([random.choice(string.ascii_lowercase).encode() for _ in range(16)]) for _ in range(20)])
        kwds_in_doc_not_in_query = set([b''.join([random.choice(string.ascii_lowercase).encode() for _ in range(16)]) for _ in range(1000)])
        kwds_not_in_doc_in_query = set([b''.join([random.choice(string.ascii_lowercase).encode() for _ in range(16)]) for _ in range(1000)])

        # Ensure there ate no intersection between these two sets.
        kwds_in_doc_not_in_query -= kwds_in_doc_and_in_query

        # Ensure there ate no intersection between this set and the two others.
        kwds_not_in_doc_in_query -= kwds_in_doc_and_in_query
        kwds_not_in_doc_in_query -= kwds_in_doc_not_in_query

        kwds_in_doc_and_in_query = list(kwds_in_doc_and_in_query)
        kwds_in_doc_not_in_query = list(kwds_in_doc_not_in_query)
        kwds_not_in_doc_in_query = list(kwds_not_in_doc_in_query)

        # generate documents
        raw_docs = [kwds_in_doc_and_in_query + [random.choice(kwds_in_doc_not_in_query) for _ in range(100)] for _ in range(1000)]
        docs = [Document(str(uuid4()), datetime.now() - timedelta(seconds=1000-i)) for i in range(1000)]
        nes = [NamedEntity(doc.identifier, NamedEntityCategory.PERSON, kwd.decode()) for doc, kwds in zip(docs, raw_docs) for kwd in kwds]

        # generates queries content.
        queries_full = [[random.choice(kwds_in_doc_and_in_query) for _ in range(10)] for _ in range(1000)]
        queries_none = [[random.choice(kwds_not_in_doc_in_query) for _ in range(10)] for _ in range(1000)]
        queries_50 = [([random.choice(kwds_in_doc_and_in_query) for _ in range(5)] + [random.choice(kwds_not_in_doc_in_query) for _ in range(5)]) for _ in range(1000)]

        # Publication of the documents
        (secret_server, published) = MSPSIDocumentOwner.publish((ne for ne in nes), docs, 60000)

        err_false_neg = 0
        err_false_pos = 0
        n_matches = 0

        for queries, expected, info_str in zip((queries_full, queries_50, queries_none), ([10] * 10, [5] * 10, [0] * 10), ('\n===== Full Match =====', '\n===== 50% match ======', '\n===== 0% match =======')):
            print(info_str)
            for query in queries:
                n_matches += 1

                (secret_client, query) = MSPSIQuerier.query(query)
                reply = MSPSIDocumentOwner.reply(secret_server, query)
                decoded_kwds = MSPSIQuerier.decode_reply(secret_client, reply)
                cards = MSPSIQuerier.process_reply(decoded_kwds, len(docs), published)

                for i, j in zip(cards, expected):
                    if len(i) != j:
                        if len(i) > j:
                            n_false = len(i) - j
                            print('{} false positive found (expected: {}, found: {})'.format(n_false, j, len(i)))
                            err_false_pos += n_false
                        else:
                            n_false = j - len(i)
                            print('{} false negatives found (expected: {}, found: {})'.format(n_false, j, len(i)))
                            err_false_neg += n_false

        print('A total of {} false negative and {} false positive were for {} queries of 10 keywords.'.format(err_false_neg, err_false_pos, n_matches))

