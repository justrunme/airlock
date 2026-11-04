"""Tests for RFC 8785 JCS canonicalization."""

from airlock.receipt import canonical_json


class TestJCS:
    """Test RFC 8785 JCS implementation."""

    def test_jcs_number_1_0(self):
        """RFC 8785: number 1.0 canonical form."""
        data = {"number": 1.0}
        result = canonical_json(data)
        assert result == b'{"number":1}'

    def test_jcs_number_1e21(self):
        """RFC 8785: number 1e21 canonical form."""
        data = {"number": 1e21}
        result = canonical_json(data)
        assert result == b'{"number":1e+21}'

    def test_jcs_number_small(self):
        """RFC 8785: small number 0.000001."""
        data = {"number": 0.000001}
        result = canonical_json(data)
        assert result == b'{"number":0.000001}' or result == b'{"number":1e-6}'

    def test_jcs_unicode_key_sorting(self):
        """RFC 8785: Unicode keys sorted by UTF-16 code units."""
        data = {"z": 1, "a": 2, "ñ": 3}
        result = canonical_json(data)
        # UTF-16 ordering
        assert result == b'{"a":2,"z":1,"\xc3\xb1":3}'

    def test_jcs_escape_minimal(self):
        """RFC 8785: minimal string escaping."""
        data = {"str": 'test\n"quote"'}
        result = canonical_json(data)
        assert result == b'{"str":"test\\n\\"quote\\""}'

    def test_jcs_no_extra_whitespace(self):
        """RFC 8785: no extra whitespace."""
        data = {"a": 1, "b": [2, 3], "c": {"d": 4}}
        result = canonical_json(data)
        # No spaces after colons or commas
        assert b" " not in result
        assert result == b'{"a":1,"b":[2,3],"c":{"d":4}}'

    def test_jcs_stable(self):
        """JCS produces stable output."""
        data = {"z": 1, "a": 2, "m": [3, 2, 1]}
        result1 = canonical_json(data)
        result2 = canonical_json(data)
        assert result1 == result2

    def test_jcs_key_order(self):
        """Keys are ordered correctly."""
        data = {"10": 1, "2": 2, "1": 3}
        result = canonical_json(data)
        # Lexicographic ordering: "1" < "10" < "2"
        assert result == b'{"1":3,"10":1,"2":2}'
