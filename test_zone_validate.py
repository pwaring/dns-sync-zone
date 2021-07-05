import unittest
import io
from contextlib import redirect_stdout

import zone_validate as V


class TextDNSValidate(unittest.TestCase):
    """
    Test the DNS Validator
    """

    def test_is_valid_label_empty(self):
        self.assertFalse(V.is_valid_label(""))

    def test_is_valid_label_long(self):
        self.assertFalse(V.is_valid_label("".ljust(64, "a")))

    def test_is_valid_label_not_start_with_digit(self):
        self.assertFalse(V.is_valid_label("0zone"))

    def test_is_valid_label_not_end_with_hyphen(self):
        self.assertFalse(V.is_valid_label("zone-"))

    def test_is_valid_label_forbidden(self):
        self.assertFalse(V.is_valid_label("test.local"))

    def test_is_valid_label_not_strict(self):
        self.assertTrue(V.is_valid_label("_tcp", strict=False))

    def test_is_valid_label_valid(self):
        self.assertTrue(V.is_valid_label("a"))
        self.assertTrue(V.is_valid_label("".ljust(63, "a")))
        self.assertTrue(V.is_valid_label("QuOrt1e-pLeeN12"))

    def test_is_valid_domain_empty(self):
        self.assertFalse(V.is_valid_domain(""))

    def test_is_valid_domain_long_bad(self):
        long_name = ""
        for i in range(256):
            if i % 64 == 63:
                long_name += "."
            else:
                long_name += "a"
        self.assertFalse(V.is_valid_domain(long_name))

    def test_is_valid_domain_long_good(self):
        long_name = ""
        for i in range(255):
            if i % 64 == 63:
                long_name += "."
            else:
                long_name += "a"
        self.assertTrue(V.is_valid_domain(long_name))

    def test_is_valid_domain_two_dots(self):
        self.assertFalse(V.is_valid_domain("test..test"))
        self.assertFalse(V.is_valid_domain("test..test."))

    def test_is_valid_domain_trailing_dot(self):
        self.assertTrue(V.is_valid_domain("test.test."))

    def test_is_valid_domain_sole_dot(self):
        self.assertTrue(V.is_valid_domain("."))

    def test_is_valid_name_specials(self):
        self.assertTrue(V.is_valid_name("@"))
        self.assertTrue(V.is_valid_name("*"))
        self.assertFalse(V.is_valid_name("%"))

    def test_is_valid_name_long_good(self):
        long_name = ""
        for i in range(255):
            if i % 64 == 63:
                long_name += "."
            else:
                long_name += "a"
        self.assertTrue(V.is_valid_name(long_name))

    def test_is_valid_target_lax(self):
        f = io.StringIO()
        with redirect_stdout(f):
            self.assertTrue(V.is_valid_target("test.domain"))
        self.assertEqual("", f.getvalue())

    def test_is_valid_target_strict_bad(self):
        f = io.StringIO()
        with redirect_stdout(f):
            self.assertTrue(V.is_valid_target("test.domain", strict=True))
        self.assertEqual(
            "*** Warning: target test.domain is missing a terminating dot\n",
            f.getvalue(),
        )

    def test_is_valid_target_strict_good(self):
        f = io.StringIO()
        with redirect_stdout(f):
            self.assertTrue(V.is_valid_target("test.domain.", strict=True))
        self.assertEqual("", f.getvalue())

    def test_is_valid_rname_lax(self):
        f = io.StringIO()
        with redirect_stdout(f):
            self.assertTrue(V.is_valid_rname("test.domain"))
        self.assertEqual("", f.getvalue())

    def test_is_valid_rname_slash_good(self):
        f = io.StringIO()
        with redirect_stdout(f):
            self.assertTrue(
                V.is_valid_rname(r"test\.user.domain.name", strict=True)
            )
        self.assertEqual(
            "*** Warning: target test\\.user.domain.name is "
            "missing a terminating dot\n",
            f.getvalue(),
        )

    def test_is_valid_rname_slash_bad(self):
        f = io.StringIO()
        with redirect_stdout(f):
            self.assertFalse(
                V.is_valid_rname(r"test\.user.1domain", strict=True)
            )
        self.assertEqual(
            "", f.getvalue(),
        )

    def test_is_valid_rname_strict_good(self):
        f = io.StringIO()
        with redirect_stdout(f):
            self.assertTrue(V.is_valid_rname("test.domain.", strict=True))
        self.assertEqual("", f.getvalue())

    def test_is_valid_ttl_empty(self):
        self.assertFalse(V.is_valid_ttl(""))

    def test_is_valid_ttl_negative(self):
        self.assertFalse(V.is_valid_ttl("-1"))

    def test_is_valid_ttl_alpha(self):
        self.assertFalse(V.is_valid_ttl("zero1"))
        self.assertFalse(V.is_valid_ttl("28d"))
        self.assertFalse(V.is_valid_ttl("0x13"))

    def test_is_valid_ttl_zero(self):
        self.assertTrue(V.is_valid_ttl("000000000000000000000000"))

    def test_is_valid_ttl_maxint(self):
        self.assertTrue(V.is_valid_ttl("2147483647"))

    def test_is_valid_ttl_maxint_plus(self):
        self.assertFalse(V.is_valid_ttl("2147483648"))

    def test_is_valid_ttl_maxint64(self):
        self.assertFalse(V.is_valid_ttl("18446744073709551615"))

    def test_is_valid_uint16_empty(self):
        self.assertFalse(V.is_valid_uint16(""))

    def test_is_valid_uint16_negative(self):
        self.assertFalse(V.is_valid_uint16("-1"))

    def test_is_valid_uint16_alpha(self):
        self.assertFalse(V.is_valid_uint16("zero1"))
        self.assertFalse(V.is_valid_uint16("28d"))
        self.assertFalse(V.is_valid_uint16("0x13"))

    def test_is_valid_uint16_zero(self):
        self.assertTrue(V.is_valid_uint16("0000000000000000000000"))

    def test_is_valid_uint16_maxint(self):
        self.assertTrue(V.is_valid_uint16("65535"))

    def test_is_valid_uint16_maxint_plus(self):
        self.assertFalse(V.is_valid_uint16("65536"))

    def test_is_valid_uint16_maxint64(self):
        self.assertFalse(V.is_valid_uint16("18446744073709551615"))

    def test_is_valid_uint8_empty(self):
        self.assertFalse(V.is_valid_uint8(""))

    def test_is_valid_uint8_negative(self):
        self.assertFalse(V.is_valid_uint8("-1"))

    def test_is_valid_uint8_alpha(self):
        self.assertFalse(V.is_valid_uint8("zero1"))
        self.assertFalse(V.is_valid_uint8("28d"))
        self.assertFalse(V.is_valid_uint8("0x13"))

    def test_is_valid_uint8_zero(self):
        self.assertTrue(V.is_valid_uint8("000000000000000000000000"))

    def test_is_valid_uint8_maxint(self):
        self.assertTrue(V.is_valid_uint8("255"))

    def test_is_valid_uint8_maxint_plus(self):
        self.assertFalse(V.is_valid_uint8("256"))

    def test_is_valid_uint8_maxint64(self):
        self.assertFalse(V.is_valid_uint8("18446744073709551615"))

    def test_is_valid_hex_empty(self):
        self.assertFalse(V.is_valid_hex(""))

    def test_is_valid_hex_negative(self):
        self.assertFalse(V.is_valid_ttl("-1"))

    def test_is_valid_hex_alpha(self):
        self.assertFalse(V.is_valid_hex("zero1"))
        self.assertFalse(V.is_valid_hex("28g"))
        self.assertFalse(V.is_valid_hex("0x13"))

    def test_is_valid_hex_zero(self):
        self.assertTrue(V.is_valid_hex("000000000000000000000000"))

    def test_is_valid_hex_value(self):
        self.assertTrue(V.is_valid_hex("f"))
        self.assertTrue(V.is_valid_hex("".ljust(255, "f")))
        self.assertTrue(
            V.is_valid_hex(
                "0a6315e3867329e8e48366be66d24475160a48f6e5555558437d145c9e42"
            )
        )

    def test_is_valid_mx_both_empty(self):
        self.assertFalse(V.is_valid_mx("", ""))

    def test_is_valid_mx_one_empty(self):
        self.assertFalse(V.is_valid_mx("10", ""))
        self.assertFalse(V.is_valid_mx("", "mx.example.com."))

    def test_is_valid_mx_bad_preference(self):
        self.assertFalse(V.is_valid_mx(".", "mx.example.com."))
        self.assertFalse(V.is_valid_mx("*", "mx.example.com."))
        self.assertFalse(V.is_valid_mx("65536", "mx.example.com."))

    def test_is_valid_mx_no_trailing_dot(self):
        f = io.StringIO()
        with redirect_stdout(f):
            self.assertTrue(V.is_valid_mx("10", "example.com"))
        self.assertEqual(
            "*** Warning: target example.com is missing a terminating dot\n",
            f.getvalue(),
        )

    def test_is_valid_mx_trailing_dot(self):
        f = io.StringIO()
        with redirect_stdout(f):
            self.assertTrue(V.is_valid_mx("10", "example.com."))
        self.assertEqual("", f.getvalue())

    def test_is_valid_ipv4_empty(self):
        self.assertFalse(V.is_valid_ipv4(""))

    def test_is_valid_ipv4_non_numeric(self):
        self.assertFalse(V.is_valid_ipv4("a.b.c.d"))

    def test_is_valid_ipv4_short(self):
        self.assertFalse(V.is_valid_ipv4("1.2.3"))

    def test_is_valid_ipv4_long(self):
        self.assertFalse(V.is_valid_ipv4("1.2.3.4.5"))

    def test_is_valid_ipv4_missing_element(self):
        self.assertFalse(V.is_valid_ipv4("1.2..4"))

    def test_is_valid_ipv4_bad_octet(self):
        self.assertFalse(V.is_valid_ipv4("1.2.256.4"))
        self.assertFalse(V.is_valid_ipv4("1.2.0x3.4"))

    def test_is_valid_ipv4_reject_ipv6(self):
        self.assertFalse(V.is_valid_ipv4("2:2::2"))

    def test_is_valid_ipv4_good_values(self):
        f = io.StringIO()
        with redirect_stdout(f):
            self.assertTrue(V.is_valid_ipv4("1.2.255.4"))
            self.assertTrue(V.is_valid_ipv4("1.2.0.4"))
            self.assertTrue(V.is_valid_ipv4("223.255.255.254"))
            self.assertTrue(V.is_valid_ipv4("101.1.0.1"))
        self.assertEqual("", f.getvalue())

    def test_is_valid_ipv4_marginal_values(self):
        for dodgy, message in [
            ("0.0.0.0", "unspecified address"),
            ("1.1.1.0", "potential broadcast address"),
            ("224.255.255.254", "multicast address"),
            ("254.255.255.254", "reserved address"),
            ("127.0.0.1", "loopback address"),
            ("192.168.0.1", "private address"),
            ("172.31.0.1", "private address"),
            ("169.254.124.25", "link-local address"),
        ]:
            f = io.StringIO()
            with redirect_stdout(f):
                self.assertTrue(V.is_valid_ipv4(dodgy), msg=dodgy)
            self.assertEqual(
                "*** Warning: {} is a {}\n".format(dodgy, message),
                f.getvalue(),
                msg=dodgy,
            )

    def test_is_valid_ipv6_empty(self):
        self.assertFalse(V.is_valid_ipv6(""))

    def test_is_valid_ipv6_non_hex(self):
        self.assertFalse(V.is_valid_ipv6("2001:b::g:0"))

    def test_is_valid_ipv6_too_large(self):
        self.assertFalse(V.is_valid_ipv6("2001:b::10000:0"))

    def test_is_valid_ipv6_too_short(self):
        self.assertFalse(V.is_valid_ipv6("2001:1:2:3:4:5:6"))
        self.assertFalse(V.is_valid_ipv6("2001:1:2"))
        self.assertFalse(V.is_valid_ipv6("2001:1"))
        self.assertFalse(V.is_valid_ipv6("2001:"))

    def test_is_valid_ipv6_too_long(self):
        self.assertFalse(V.is_valid_ipv6("2001:1:2:3:4:5:6:7:8"))
        self.assertFalse(V.is_valid_ipv6("2001:1:2:3:4:5:6::7:8"))

    def test_is_valid_ipv6_multiple_gaps(self):
        self.assertFalse(V.is_valid_ipv6("2001:::8"))
        self.assertFalse(V.is_valid_ipv6("2001:1:::3:4:5:6::7"))

    def test_is_valid_ipv6_reject_ipv4(self):
        self.assertFalse(V.is_valid_ipv6("192.168.1.2"))

    def test_is_valid_ipv6_good_values(self):
        f = io.StringIO()
        with redirect_stdout(f):
            self.assertTrue(V.is_valid_ipv6("2001:1000:2:3:4:5:6:7"))
            self.assertTrue(V.is_valid_ipv6("2001:1000::1"))
            self.assertTrue(V.is_valid_ipv6("2001:ffff::0000:1"))
        self.assertEqual("", f.getvalue())

    def test_is_valid_ipv6_bad_values(self):
        for dodgy, message in [
            ("::", "unspecified address"),
            ("::1:2:3:4:5:6", "reserved address"),
            ("0::1", "loopback address"),
            ("::1", "loopback address"),
            ("0:1:2::5", "reserved address"),
            ("64:ff9b:1::0000:1", "reserved address"),
            ("100:ffff::0000:1", "reserved address"),
            ("fe80:ffff::0000:1", "link-local address"),
            ("fc00:ffff::0000:1", "private address"),
            ("ff01:ffff::0000:1", "multicast address"),
            ("100::5123:214", "discard address"),
            ("9212:4f:8000::15:14a9", "reserved address"),
            ("FEC0::1234:5678:9ABC", "deprecated site-local address"),
        ]:
            f = io.StringIO()
            with redirect_stdout(f):
                self.assertFalse(V.is_valid_ipv6(dodgy), msg=dodgy)
            self.assertEqual(
                "*** Error: {} is a {}\n".format(dodgy, message),
                f.getvalue(),
                msg=dodgy,
            )

    def test_is_valid_ipv6_dubious_values(self):
        for dodgy, message in [
            ("2001::1", "Teredo address"),
            ("2001:1::1", "IETF protocol address"),
            ("2001:16::1", "ORCHID address"),
            ("2001:23::1", "ORCHIDv2 address"),
            ("2001:db8::3", "documentation address"),
            ("2002:123::456:1", "6to4 address"),
            ("::ffff:192.168.1.11", "mapped IPv4 address"),
        ]:
            f = io.StringIO()
            with redirect_stdout(f):
                self.assertTrue(V.is_valid_ipv6(dodgy), msg=dodgy)
            self.assertEqual(
                "*** Warning: {} is a {}\n".format(dodgy, message),
                f.getvalue(),
                msg=dodgy,
            )

    def test_tokenize_empty(self):
        self.assertEqual([], V.tokenize(""))

    def test_tokenize_mismatched_quotes(self):
        with self.assertRaises(V.ValidateError) as cm:
            V.tokenize('@ 86400 TXT "text')
        self.assertEqual("Unclosed quotes", cm.exception.message)

        with self.assertRaises(V.ValidateError) as cm:
            V.tokenize('@ 86400 TXT "te"xt"')
        self.assertEqual("Unclosed quotes", cm.exception.message)

    def test_tokenize_comment(self):
        self.assertEqual(
            ["@", "86400", "TXT", '"test;text"'],
            V.tokenize('@  86400 TXT "test;text"'),
        )
        self.assertEqual(
            ["@", "86400", "TXT", "test"],
            V.tokenize("@  86400 TXT test;text"),
        )
        self.assertEqual([], V.tokenize(';@  86400 TXT "test;text"'))

    def test_tokenize_examples(self):
        self.assertEqual(
            ["example.com.", "300", "A", "192.168.254.245"],
            V.tokenize("example.com.\t300\t A \t\t192.168.254.245\t"),
        )
        self.assertEqual(
            ["@", "3600", "CAA", "0", "issue", '"letsencrypt.org"'],
            V.tokenize(
                '@                3600 CAA      0 issue "letsencrypt.org"'
            ),
        )
        self.assertEqual(
            ["_kerberos._tcp", "600", "SRV", "0", "100", "88", "srv0"],
            V.tokenize("_kerberos._tcp          600 SRV    0 100   88 srv0"),
        )

        self.assertEqual(
            ["", "600", "SRV", "0", "100", "88", "srv0"],
            V.tokenize("          600 SRV    0 100   88 srv0"),
        )

    def test_skip_zone_record_blank(self):
        self.assertTrue(V.skip_zone_record(""))
        self.assertTrue(V.skip_zone_record("   "))
        self.assertTrue(V.skip_zone_record("".ljust(200)))

    def test_skip_zone_record_comment(self):
        self.assertTrue(V.skip_zone_record("#"))
        self.assertTrue(V.skip_zone_record(" # "))
        self.assertTrue(V.skip_zone_record("    # blah blah "))

    def test_skip_zone_record_noncomment(self):
        self.assertFalse(V.skip_zone_record("test"))
        self.assertFalse(V.skip_zone_record("     test     "))
        self.assertFalse(V.skip_zone_record("   blah # blah blah "))

    def test_validate_zone_record_skip(self):
        self.assertTrue(V.validate_zone_record(""))
        self.assertTrue(V.validate_zone_record("#"))
        self.assertTrue(V.validate_zone_record("   # test "))

    def test_validate_zone_record_short(self):
        self.assertFalse(V.validate_zone_record("ADD"))
        self.assertFalse(V.validate_zone_record("ADD Q Q"))
        self.assertFalse(V.validate_zone_record("ADD Q Q Q"))

    def test_validate_zone_record_bad_command(self):
        self.assertFalse(V.validate_zone_record("TED Q Q Q Q"))
        self.assertFalse(V.validate_zone_record("add Q Q Q"))
        self.assertFalse(V.validate_zone_record("delete Q Q Q"))
        self.assertFalse(V.validate_zone_record("replace Q Q Q"))

    def test_validate_zone_record_bad_ttl(self):
        self.assertFalse(V.validate_zone_record("ADD host ttl A 12.13.24.15"))
        self.assertFalse(
            V.validate_zone_record("ADD host 4294967296 A 12.13.24.15")
        )

    def test_validate_zone_record_bad_hostname(self):
        # self.assertFalse(V.validate_zone_record("ADD 123 10 A 12.13.24.15"))
        self.assertFalse(V.validate_zone_record("ADD host- 10 A 12.13.24.15"))

    def test_validate_zone_record_allow_underscore(self):
        # _host.example.org is permitted in DNS, even though some resolvers don't like it
        self.assertTrue(V.validate_zone_record("ADD _host 10 A 12.13.24.15"))

    def test_validate_zone_record_allow_digit_start_hostname(self):
        # RFC 1123 permits hostname labels to start with digits
        self.assertTrue(V.validate_zone_record("ADD 111 300 A 127.0.0.1"))

    def test_validate_zone_record_nonstrict_hostname(self):
        self.assertTrue(V.validate_zone_record("ADD _host 10 TXT 12.13.24.15"))
        self.assertTrue(V.validate_zone_record("ADD _host 10 CNAME example.com."))
        self.assertTrue(
            V.validate_zone_record("ADD _host 10 SRV 0 100 88 testsrv")
        )
        self.assertTrue(
            V.validate_zone_record("ADD _host- 10 SRV 0 100 88 testsrv")
        )
        self.assertTrue(
            V.validate_zone_record("ADD _host_ 10 SRV 0 100 88 testsrv")
        )

    def test_validate_zone_record_bad_quotes(self):
        f = io.StringIO()
        with redirect_stdout(f):
            self.assertFalse(V.validate_zone_record('ADD @ 3600 TXT "test'))
        self.assertEqual("* Unclosed quotes\n", f.getvalue())

    def test_validate_zone_record_cname(self):
        self.assertFalse(
            V.validate_zone_record("REPLACE host 10 CNAME www.example com.",)
        )
        self.assertFalse(
            V.validate_zone_record("REPLACE host 10 CNAME 192.168.1.1",)
        )

    def test_validate_zone_record_aname(self):
        self.assertFalse(
            V.validate_zone_record("REPLACE host 10 ANAME www.example com.",)
        )
        self.assertFalse(
            V.validate_zone_record("REPLACE host 10 ANAME 192.168.1.1",)
        )

    def test_validate_zone_record_ns(self):
        self.assertFalse(
            V.validate_zone_record("REPLACE host 10 NS www.example com.",)
        )
        self.assertFalse(
            V.validate_zone_record("REPLACE host 10 NS 192.168.1.1",)
        )

    def test_validate_zone_record_soa_short(self):
        self.assertFalse(
            V.validate_zone_record("DELETE @ 65535 SOA ns.example.com.")
        )
        self.assertFalse(
            V.validate_zone_record(
                "DELETE @ 65535 SOA ns.example.com. hostmaster.example.com."
            )
        )
        self.assertFalse(
            V.validate_zone_record(
                "DELETE @ 65535 SOA ns.example.com. hostmaster.example.com."
                " 86400"
            )
        )
        self.assertFalse(
            V.validate_zone_record(
                "DELETE @ 65535 SOA ns.example.com. hostmaster.example.com."
                " 86400 86400"
            )
        )
        self.assertFalse(
            V.validate_zone_record(
                "DELETE @ 65535 SOA ns.example.com. hostmaster.example.com."
                " 86400 86400 86400"
            )
        )
        self.assertFalse(
            V.validate_zone_record(
                "DELETE @ 65535 SOA ns.example.com. hostmaster.example.com."
                " 86400 86400 86400 86400"
            )
        )

    def test_validate_zone_record_soa_long(self):
        self.assertFalse(
            V.validate_zone_record(
                "DELETE @ 65535 SOA ns.example.com. hostmaster.example.com."
                " 86400 86400 86400 86400 86400 86400"
            )
        )

    def test_validate_zone_record_soa_good(self):
        f = io.StringIO()
        with redirect_stdout(f):
            self.assertTrue(
                V.validate_zone_record(
                    "DELETE @ 65535 SOA ns.example.com."
                    " hostmaster.example.com."
                    " 86400 86400 86400 86400 86400"
                )
            )
            self.assertTrue(
                V.validate_zone_record(
                    "DELETE @ 65535 SOA ns.example.com."
                    " host\\.master.example.com."
                    " 86400 86400 86400 86400 86400"
                )
            )
        self.assertEqual("", f.getvalue())

    def test_validate_zone_record_soa_warn_fields(self):
        f = io.StringIO()
        with redirect_stdout(f):
            self.assertTrue(
                V.validate_zone_record(
                    "DELETE @ 65535 SOA ns.example.com hostmaster.example.com."
                    " 86400 86400 86400 86400 86400"
                )
            )
            self.assertTrue(
                V.validate_zone_record(
                    "DELETE @ 65535 SOA ns.example.net. hostmaster.example.net"
                    " 86400 86400 86400 86400 86400"
                )
            )
        self.assertEqual(
            "*** Warning: target ns.example.com is missing a terminating dot\n"
            "*** Warning: target hostmaster.example.net is missing"
            " a terminating dot\n",
            f.getvalue(),
        )

    def test_validate_zone_record_soa_bad_numbers(self):
        original = V.tokenize(
            "REPLACE @ 65535 SOA ns.example.com. hostmaster.example.com."
            " 86400 86400 86400 86400 86400"
        )

        for field in [6, 7, 8, 9, 10]:
            copy = original[:]

            for value in [
                "x",
                "-1",
                "2w",
                "4294967296",
                "281474976710656",
                "18446744073709551615",
            ]:
                copy[field] = value
                test = " ".join(copy)

                self.assertFalse(V.validate_zone_record(test), msg=test)

    def test_validate_zone_record_a_good(self):
        f = io.StringIO()
        with redirect_stdout(f):
            self.assertTrue(V.validate_zone_record("ADD @ 3600 A 1.2.3.4"))
        self.assertEqual("", f.getvalue())

    def test_validate_zone_record_a_short(self):
        self.assertFalse(V.validate_zone_record("ADD @ 3600 A"))

    def test_validate_zone_record_a_long(self):
        self.assertFalse(
            V.validate_zone_record("ADD @ 3600 A 192.100.1.4 1.1.1.1")
        )

    def test_validate_zone_record_a_bad(self):
        for fault in [
            "Q",
            "192.168.256.1",
            "1.2.3",
            "1.2.3.4.5",
            "1.2.5,7",
            "1.2.0x3.4",
        ]:
            line = "ADD @ 3600 A {}".format(fault)
            self.assertFalse(V.validate_zone_record(line), msg=line)

    def test_validate_zone_record_a_warning(self):
        for dodgy, message in [
            ("192.168.255.1", "private address"),
            ("172.20.3.4", "private address"),
            ("10.24.38.9", "private address"),
            ("225.2.95.1", "multicast address"),
            ("127.25.21.19", "loopback address"),
            ("20.35.1.0", "potential broadcast address"),
            ("201.52.19.255", "potential broadcast address"),
        ]:
            line = "ADD @ 3600 A {}".format(dodgy)
            f = io.StringIO()
            with redirect_stdout(f):
                self.assertTrue(V.validate_zone_record(line), msg=line)
            self.assertEqual(
                "*** Warning: {} is a {}\n".format(dodgy, message),
                f.getvalue(),
                msg=line,
            )

    def test_validate_zone_record_aaaa_good(self):
        f = io.StringIO()
        with redirect_stdout(f):
            self.assertTrue(
                V.validate_zone_record(
                    "ADD @ 3600 AAAA 2a00:1450:4009:81a::2004"
                )
            )
        self.assertEqual("", f.getvalue())

    def test_validate_zone_record_aaaa_short(self):
        self.assertFalse(V.validate_zone_record("ADD @ 3600 AAAA"))

    def test_validate_zone_record_aaaa_long(self):
        self.assertFalse(
            V.validate_zone_record("ADD @ 3600 AAAA 2001::5 2001::5")
        )

    def test_validate_zone_record_aaaa_bad_format(self):
        for fault in [
            "Q",
            "192.168.256.1",
            "2050::5::1",
            "20500::5:1",
        ]:
            line = "ADD @ 3600 AAAA {}".format(fault)
            self.assertFalse(V.validate_zone_record(line), msg=line)

    def test_validate_zone_record_aaaa_bad_values(self):
        for dodgy, message in [
            ("::1:2:3:4:5:6", "reserved address"),
            ("0::1", "loopback address"),
            ("64:ff9b:1::0000:1", "reserved address"),
            ("100:ffff::0000:1", "reserved address"),
            ("fe80:ffff::0000:1", "link-local address"),
            ("fc00:ffff::0000:1", "private address"),
            ("ff01:ffff::0000:1", "multicast address"),
        ]:
            line = "ADD @ 3600 AAAA {}".format(dodgy)
            f = io.StringIO()
            with redirect_stdout(f):
                self.assertFalse(V.validate_zone_record(line), msg=dodgy)
            self.assertEqual(
                "*** Error: {} is a {}\n".format(dodgy, message),
                f.getvalue(),
                msg=dodgy,
            )

    def test_is_valid_zone_record_aaaa_dubious_values(self):
        for dodgy, message in [
            ("2001::1", "Teredo address"),
            ("2001:1::1", "IETF protocol address"),
            ("2001:23::1", "ORCHIDv2 address"),
            ("2001:db8::3", "documentation address"),
            ("2002:123::456:1", "6to4 address"),
        ]:
            line = "ADD @ 3600 AAAA {}".format(dodgy)
            f = io.StringIO()
            with redirect_stdout(f):
                self.assertTrue(V.validate_zone_record(line), msg=dodgy)
            self.assertEqual(
                "*** Warning: {} is a {}\n".format(dodgy, message),
                f.getvalue(),
                msg=dodgy,
            )

    def test_is_valid_zone_record_txt_good(self):
        f = io.StringIO()
        with redirect_stdout(f):
            self.assertTrue(V.validate_zone_record('ADD @ 3600 TXT "TEST"'))
            self.assertTrue(V.validate_zone_record('ADD @ 3600 TXT "TE;ST"'))
            self.assertTrue(
                V.validate_zone_record("ADD @ 3600 TXT TEST", strict=True)
            )
            self.assertTrue(
                V.validate_zone_record('ADD @ 3600 TXT "TEST" "TEST"')
            )
            self.assertTrue(
                V.validate_zone_record("ADD @ 3600 TXT TEST TEST TEST")
            )
        self.assertEqual("", f.getvalue())

    def test_is_valid_zone_record_txt_warn(self):
        f = io.StringIO()
        with redirect_stdout(f):
            self.assertTrue(
                V.validate_zone_record(
                    'ADD @ 3600 TXT "TEST" "TEST"', strict=True
                )
            )
        self.assertEqual(
            "* Warning: TXT record has multiple parts\n"
            'ADD @ 3600 TXT "TEST" "TEST"\n',
            f.getvalue(),
        )

    def test_is_valid_zone_record_mx_short(self):
        self.assertFalse(V.validate_zone_record("ADD @ 3600 MX 1"))
        self.assertFalse(V.validate_zone_record("ADD @ 3600 MX fq.dn."))

    def test_is_valid_zone_record_mx_long(self):
        self.assertFalse(V.validate_zone_record("ADD @ 3600 MX 1 2 3"))
        self.assertFalse(V.validate_zone_record("ADD @ 3600 MX 10 fq. dn."))

    def test_is_valid_zone_record_mx_good(self):
        self.assertTrue(V.validate_zone_record("ADD @ 3600 MX 0 fq.dn."))
        self.assertTrue(V.validate_zone_record("ADD @ 3600 MX 65535 fq.dn."))

    def test_is_valid_zone_record_mx_bad(self):
        self.assertFalse(V.validate_zone_record("ADD @ 3600 MX fq.dn. 0"))
        self.assertFalse(V.validate_zone_record('ADD @ 3600 MX 10 ""'))
        self.assertFalse(
            V.validate_zone_record("ADD @ 3600 MX 10 192.168.1.1")
        )

    def test_is_valid_zone_record_mx_warn(self):
        f = io.StringIO()
        with redirect_stdout(f):
            self.assertTrue(V.validate_zone_record("ADD @ 3600 MX 0 fq.dn"))
        self.assertEqual(
            "*** Warning: target fq.dn is missing a terminating dot\n",
            f.getvalue(),
        )

    def test_is_valid_zone_record_srv_short(self):
        self.assertFalse(V.validate_zone_record("ADD _t 3600 SRV 1"))
        self.assertFalse(V.validate_zone_record("ADD _t 3600 SRV 1 2"))
        self.assertFalse(V.validate_zone_record("ADD _t 3600 SRV 1 2 3"))

    def test_is_valid_zone_record_srv_long(self):
        self.assertFalse(V.validate_zone_record("ADD _t 3600 SRV 1 2 3 h 5"))
        self.assertFalse(V.validate_zone_record("ADD _t 3600 SRV 1 2 3 h 5 6"))

    def test_is_valid_zone_record_srv_good(self):
        self.assertTrue(V.validate_zone_record("ADD _t 3600 SRV 1 2 3 h"))
        self.assertTrue(V.validate_zone_record("ADD _t 3600 SRV 1 2 3 fq.dn."))

    def test_is_valid_zone_record_srv_bad(self):
        self.assertFalse(V.validate_zone_record("ADD tt 3600 SRV 1 2 3 h"))
        self.assertFalse(V.validate_zone_record("ADD _t 3600 SRV a 2 3 h"))
        self.assertFalse(V.validate_zone_record("ADD _t 3600 SRV 1 a 3 h"))
        self.assertFalse(V.validate_zone_record("ADD _t 3600 SRV 1 2 a h"))
        self.assertFalse(V.validate_zone_record("ADD _t 3600 SRV 1 2 a h-"))
        self.assertFalse(V.validate_zone_record("ADD _t 3600 SRV 1 2 3 4"))

    def test_is_valid_zone_record_caa_short(self):
        self.assertFalse(V.validate_zone_record("ADD @ 3600 CAA 1"))
        self.assertFalse(V.validate_zone_record("ADD @ 3600 CAA 1 issue"))

    def test_is_valid_zone_record_caa_long(self):
        self.assertFalse(
            V.validate_zone_record("ADD @ 3600 CAA 1 issue letsencrypt org")
        )

    def test_is_valid_zone_record_caa_good(self):
        self.assertTrue(
            V.validate_zone_record("ADD @ 3600 CAA 0 issue letsencrypt.org")
        )
        self.assertTrue(
            V.validate_zone_record('ADD @ 3600 CAA 1 issue "letsencrypt.org"')
        )
        self.assertTrue(
            V.validate_zone_record(
                'ADD @ 3600 CAA 1 issuewild "letsencrypt.org"'
            )
        )
        self.assertTrue(
            V.validate_zone_record(
                'ADD @ 3600 CAA 0 iodef "mailto:postmaster@example.com"'
            )
        )

    def test_is_valid_zone_record_caa_bad(self):
        self.assertFalse(
            V.validate_zone_record("ADD @ 3600 CAA 256 issue letsencrypt.org")
        )
        self.assertFalse(
            V.validate_zone_record('ADD @ 3600 CAA 1 isue "letsencrypt.org"')
        )
        self.assertFalse(
            V.validate_zone_record(
                'ADD @ 3600 CAA 0 iodeff "mailto:postmaster@example.com"'
            )
        )

    def test_is_valid_zone_record_sshfp_short(self):
        self.assertFalse(V.validate_zone_record("ADD @ 3600 SSHFP 1"))
        self.assertFalse(V.validate_zone_record("ADD @ 3600 SSHFP 1 2"))

    def test_is_valid_zone_record_sshfp_long(self):
        self.assertFalse(
            V.validate_zone_record("ADD @ 3600 SSHFP 1 2 abcdef abcdef")
        )

    def test_is_valid_zone_record_sshfp_good(self):
        self.assertTrue(
            V.validate_zone_record("ADD @ 3600 SSHFP 1 2 abcdefabcdef")
        )
        self.assertTrue(
            V.validate_zone_record("ADD @ 3600 SSHFP 255 255 a51254")
        )

    def test_is_valid_zone_record_sshfp_bad(self):
        self.assertFalse(
            V.validate_zone_record("ADD @ 3600 SSHFP 1 2 abcdefgabcdef")
        )
        self.assertFalse(
            V.validate_zone_record("ADD @ 3600 SSHFP 256 2 abcdef")
        )
        self.assertFalse(
            V.validate_zone_record("ADD @ 3600 SSHFP 2 256 abcdef")
        )
        self.assertFalse(
            V.validate_zone_record("ADD @ 3600 SSHFP 1 2 abcdef.")
        )
        self.assertFalse(
            V.validate_zone_record('ADD @ 3600 SSHFP 1 2 "abcdef"')
        )

    def test_is_valid_zone_record_unknown_not_strict(self):
        f = io.StringIO()
        with redirect_stdout(f):
            self.assertTrue(
                V.validate_zone_record(
                    "ADD @ 3600 DNSKEY 256 3 12 dGVzdGluZzEyMw=="
                )
            )
        self.assertEqual("Cannot validate type DNSKEY\n", f.getvalue())

    def test_is_valid_zone_record_unknown_strict(self):
        f = io.StringIO()
        with redirect_stdout(f):
            self.assertFalse(
                V.validate_zone_record(
                    "ADD @ 3600 DNSKEY 256 3 12 dGVzdGluZzEyMw==", strict=True
                )
            )
        self.assertEqual("Cannot validate type DNSKEY\n", f.getvalue())
