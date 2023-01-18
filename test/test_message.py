import datetime

from dsnet.message import unpackb, packb
from dsnet.mspsi import MSPSIDocumentOwner, NamedEntityCategory, NamedEntity, Document, MSPSIQuerier


def test_serialize_unserialize():
    query = b'foo'
    server_key, cuckoo_filter = MSPSIDocumentOwner.publish(
        (NamedEntity('doc_id', NamedEntityCategory.PERSON, 'foo'),),
        [Document("doc_id", datetime.datetime.utcnow())],
        1
    )
    serialized_unserialized_cuckoo_filter = unpackb(packb(cuckoo_filter))

    client_key, encoded_kwds = MSPSIQuerier.query([query])
    reply = MSPSIDocumentOwner.reply(server_key, encoded_kwds)
    decoded_kwds = MSPSIQuerier.decode_reply(client_key, reply)
    cards_expected = MSPSIQuerier.process_reply(decoded_kwds, 1, cuckoo_filter)
    cards = MSPSIQuerier.process_reply(decoded_kwds, 1, serialized_unserialized_cuckoo_filter)

    assert cuckoo_filter.buckets.endian() == serialized_unserialized_cuckoo_filter.buckets.endian()
    assert cuckoo_filter.buckets == serialized_unserialized_cuckoo_filter.buckets
    assert cards == cards_expected
    assert cards == [[0]]
