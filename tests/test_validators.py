"""Tests for pdns_mcp.validators."""

import pytest
from pdns_mcp.validators import validate_record, validate_ttl


# ---------------------------------------------------------------------------
# TTL
# ---------------------------------------------------------------------------

class TestTTL:
    def test_valid_ttl(self):
        r = validate_ttl(300)
        assert r.passed
        assert not r.errors

    def test_ttl_too_low(self):
        r = validate_ttl(30)
        assert not r.passed
        assert any("below minimum" in e for e in r.errors)

    def test_ttl_too_high(self):
        r = validate_ttl(999999)
        assert not r.passed
        assert any("exceeds maximum" in e for e in r.errors)

    def test_ttl_at_boundary(self):
        assert validate_ttl(60).passed
        assert validate_ttl(86400).passed
        assert not validate_ttl(59).passed
        assert not validate_ttl(86401).passed


# ---------------------------------------------------------------------------
# A records
# ---------------------------------------------------------------------------

class TestARecord:
    def test_valid(self):
        r = validate_record("A", ["10.10.1.5"], 300)
        assert r.passed
        assert not r.errors

    def test_multiple_records(self):
        r = validate_record("A", ["10.10.1.5", "10.10.1.6"], 300)
        assert r.passed

    def test_invalid_ip(self):
        r = validate_record("A", ["not-an-ip"], 300)
        assert not r.passed
        assert any("Invalid IPv4" in e for e in r.errors)

    def test_ipv6_in_a_record(self):
        r = validate_record("A", ["2001:db8::1"], 300)
        assert not r.passed

    def test_empty_records(self):
        r = validate_record("A", [], 300)
        assert not r.passed

    def test_low_ttl_warns(self):
        r = validate_record("A", ["10.10.1.1"], 120)
        assert r.passed          # low TTL is a warning, not an error
        assert any("low" in w for w in r.warnings)

    def test_multicast_rejected(self):
        r = validate_record("A", ["224.0.0.1"], 300)
        assert not r.passed


# ---------------------------------------------------------------------------
# AAAA records
# ---------------------------------------------------------------------------

class TestAAAARecord:
    def test_valid(self):
        r = validate_record("AAAA", ["2001:db8::1"], 300)
        assert r.passed

    def test_invalid(self):
        r = validate_record("AAAA", ["not::valid::addr::extra"], 300)
        assert not r.passed


# ---------------------------------------------------------------------------
# CNAME
# ---------------------------------------------------------------------------

class TestCNAME:
    def test_valid(self):
        r = validate_record("CNAME", ["target.example.com."], 300)
        assert r.passed

    def test_multiple_records_rejected(self):
        r = validate_record("CNAME", ["a.example.com.", "b.example.com."], 300)
        assert not r.passed
        assert any("exactly one" in e for e in r.errors)

    def test_no_trailing_dot_warns(self):
        r = validate_record("CNAME", ["target.example.com"], 300)
        assert r.passed
        assert any("." in w for w in r.warnings)

    def test_empty_rejected(self):
        r = validate_record("CNAME", [], 300)
        assert not r.passed


# ---------------------------------------------------------------------------
# MX
# ---------------------------------------------------------------------------

class TestMX:
    def test_valid(self):
        r = validate_record("MX", ["10 mail.example.com."], 300)
        assert r.passed

    def test_missing_priority(self):
        r = validate_record("MX", ["mail.example.com."], 300)
        assert not r.passed

    def test_priority_out_of_range(self):
        r = validate_record("MX", ["70000 mail.example.com."], 300)
        assert not r.passed

    def test_priority_zero_ok(self):
        r = validate_record("MX", ["0 mail.example.com."], 300)
        assert r.passed

    def test_no_trailing_dot_warns(self):
        r = validate_record("MX", ["10 mail.example.com"], 300)
        assert r.passed
        assert r.warnings

    def test_empty_rejected(self):
        r = validate_record("MX", [], 300)
        assert not r.passed


# ---------------------------------------------------------------------------
# TXT
# ---------------------------------------------------------------------------

class TestTXT:
    def test_valid(self):
        r = validate_record("TXT", ['"v=spf1 include:example.com ~all"'], 300)
        assert r.passed

    def test_long_string_warns(self):
        long_val = '"' + "x" * 300 + '"'
        r = validate_record("TXT", [long_val], 300)
        assert r.passed           # warning, not error
        assert any("255" in w for w in r.warnings)

    def test_empty_rejected(self):
        r = validate_record("TXT", [], 300)
        assert not r.passed


# ---------------------------------------------------------------------------
# SOA — always rejected
# ---------------------------------------------------------------------------

class TestSOA:
    def test_always_fails(self):
        r = validate_record("SOA", ["ns1.example.com. admin.example.com. 1 3600 900 604800 300"], 3600)
        assert not r.passed
        assert any("Direct SOA" in e for e in r.errors)


# ---------------------------------------------------------------------------
# SRV
# ---------------------------------------------------------------------------

class TestSRV:
    def test_valid(self):
        r = validate_record("SRV", ["10 20 5060 sip.example.com."], 300)
        assert r.passed

    def test_wrong_field_count(self):
        r = validate_record("SRV", ["10 20 sip.example.com."], 300)
        assert not r.passed

    def test_port_out_of_range(self):
        r = validate_record("SRV", ["10 20 99999 sip.example.com."], 300)
        assert not r.passed

    def test_port_zero_rejected(self):
        r = validate_record("SRV", ["10 20 0 sip.example.com."], 300)
        assert not r.passed


# ---------------------------------------------------------------------------
# CAA
# ---------------------------------------------------------------------------

class TestCAA:
    def test_valid(self):
        r = validate_record("CAA", ['0 issue "letsencrypt.org"'], 300)
        assert r.passed

    def test_bad_format(self):
        r = validate_record("CAA", ['issue "letsencrypt.org"'], 300)
        assert not r.passed

    def test_non_standard_tag_warns(self):
        r = validate_record("CAA", ['0 contactemail "admin@example.com"'], 300)
        assert r.passed
        assert r.warnings

    def test_flags_out_of_range(self):
        r = validate_record("CAA", ['256 issue "letsencrypt.org"'], 300)
        assert not r.passed


# ---------------------------------------------------------------------------
# Unknown type — passes with warning
# ---------------------------------------------------------------------------

class TestUnknownType:
    def test_unknown_type_passes_with_warning(self):
        r = validate_record("HINFO", ["PDP-11 UNIX"], 300)
        assert r.passed
        assert any("No content validator" in w for w in r.warnings)


# ---------------------------------------------------------------------------
# Case insensitivity
# ---------------------------------------------------------------------------

class TestCaseInsensitivity:
    def test_lowercase_type(self):
        r = validate_record("a", ["10.0.0.1"], 300)
        assert r.passed

    def test_mixed_case_type(self):
        r = validate_record("Mx", ["10 mail.example.com."], 300)
        assert r.passed
