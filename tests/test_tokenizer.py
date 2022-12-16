from dsnet.tokenizer import tokenize_with_double_quotes


def test_tokenizer_hello_world():
    assert [b'hello', b'world'] == tokenize_with_double_quotes(b'hello world')


def test_tokenizer_with_one_term_between_double_quotes():
    assert tokenize_with_double_quotes(b'Donald Trump "Donald Trump"') == [b'Donald', b'Trump', b'Donald Trump']


def test_tokenizer_with_two_terms_between_double_quotes():
    assert tokenize_with_double_quotes(b'"foo bar" baz "qux fred" thud') == [b'foo bar', b'baz', b'qux fred', b'thud']