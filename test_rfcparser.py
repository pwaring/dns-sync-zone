import unittest
import io

import rfcparser


class TestRFCParser(unittest.TestCase):
    """
    Test the RFC Parser
    """

    # This is the example from RFC 1035
    rfc1035zone = """
$ORIGIN example.net
$TTL 86400
@   IN  SOA     VENERA      Action\\.domains (
                                 20     ; SERIAL
                                 7200   ; REFRESH
                                 600    ; RETRY
                                 3600000; EXPIRE
                                 60)    ; MINIMUM

        NS      A.ISI.EDU.
        NS      VENERA
        NS      VAXA
        MX      10      VENERA
        MX      20      VAXA

A       A       26.3.0.103

SUB     NS      VAXA


VENERA  A       10.1.0.52
        A       128.9.0.32

VAXA    A       10.2.0.27
        A       128.9.0.33
"""

    def test_rfcparser_init(self):
        r = rfcparser.RFCParser()
        self.assertIsNone(r.zone)

    def test_rfcparser_types_good(self):
        # This is a bit self-referential
        r = rfcparser.RFCParser()
        for t in rfcparser._valid_types.keys():
            self.assertTrue(r.is_valid_type(t))

    def test_rfcparser_types_bad(self):
        r = rfcparser.RFCParser()
        self.assertFalse(r.is_valid_type("ZZZ"))
        self.assertFalse(r.is_valid_type(""))

    def test_rfcparser_parser_not_stream_or_string(self):
        with self.assertRaises(rfcparser.RFCParserError) as cm:
            _ = rfcparser.RFCParser([])
        self.assertEqual(
            cm.exception.message, "Argument is neither string nor file object"
        )
        with self.assertRaises(rfcparser.RFCParserError) as cm:
            _ = rfcparser.RFCParser({})
        self.assertEqual(
            cm.exception.message, "Argument is neither string nor file object"
        )
        with self.assertRaises(rfcparser.RFCParserError) as cm:
            _ = rfcparser.RFCParser(1)
        self.assertEqual(
            cm.exception.message, "Argument is neither string nor file object"
        )

    def test_rfcparser_parser_string(self):
        try:
            r = rfcparser.RFCParser(self.rfc1035zone)
        except rfcparser.RFCParserError as exc:  # pragma: no cover
            self.fail(
                "RFCParser() raised RFCParserError: {}".format(exc.message)
            )
        self.assertIsNotNone(r.zone)
        self.assertTrue("origin" in r.zone)
        self.assertEqual(r.zone["origin"], "example.net.")
        self.assertTrue("ttl" in r.zone)
        self.assertEqual(r.zone["ttl"], "86400")
        self.assertTrue("records" in r.zone)

        self.assertEqual(
            [
                [
                    "@",
                    "86400",
                    "SOA",
                    "VENERA",
                    "Action\\.domains",
                    "20",
                    "7200",
                    "600",
                    "3600000",
                    "60",
                ],
                ["@", "86400", "NS", "A.ISI.EDU."],
                ["@", "86400", "NS", "VENERA"],
                ["@", "86400", "NS", "VAXA"],
                ["@", "86400", "MX", "10", "VENERA"],
                ["@", "86400", "MX", "20", "VAXA"],
                ["A", "86400", "A", "26.3.0.103"],
                ['SUB', '86400', 'NS', 'VAXA'],
                ["VENERA", "86400", "A", "10.1.0.52"],
                ["VENERA", "86400", "A", "128.9.0.32"],
                ["VAXA", "86400", "A", "10.2.0.27"],
                ["VAXA", "86400", "A", "128.9.0.33"],
            ],
            r.zone["records"],
        )

    def test_rfcparser_parser_stream(self):
        try:
            with io.StringIO(self.rfc1035zone) as f:
                r = rfcparser.RFCParser(f)
        except rfcparser.RFCParserError as exc:  # pragma: no cover
            self.fail(
                "RFCParser() raised RFCParserError: {}".format(exc.message)
            )
        self.assertIsNotNone(r.zone)
        self.assertTrue("origin" in r.zone)
        self.assertEqual(r.zone["origin"], "example.net.")
        self.assertTrue("ttl" in r.zone)
        self.assertEqual(r.zone["ttl"], "86400")
        self.assertTrue("records" in r.zone)

        self.assertEqual(
            [
                [
                    "@",
                    "86400",
                    "SOA",
                    "VENERA",
                    "Action\\.domains",
                    "20",
                    "7200",
                    "600",
                    "3600000",
                    "60",
                ],
                ["@", "86400", "NS", "A.ISI.EDU."],
                ["@", "86400", "NS", "VENERA"],
                ["@", "86400", "NS", "VAXA"],
                ["@", "86400", "MX", "10", "VENERA"],
                ["@", "86400", "MX", "20", "VAXA"],
                ["A", "86400", "A", "26.3.0.103"],
                ['SUB', '86400', 'NS', 'VAXA'],
                ["VENERA", "86400", "A", "10.1.0.52"],
                ["VENERA", "86400", "A", "128.9.0.32"],
                ["VAXA", "86400", "A", "10.2.0.27"],
                ["VAXA", "86400", "A", "128.9.0.33"],
            ],
            r.zone["records"],
        )

    def test_rfcparser_complex_example(self):
        # Taken from Wikipedia example
        zone = """
$ORIGIN example.com.     ; designates the start of this zone file in the namespace
$TTL 3600                ; default expiration time of all resource records without their own TTL value
example.com.  IN  SOA   ns.example.com. username.example.com. (
                        2007120710
                        1d 2h 4w 1h )
example.com.  IN  300 NS    ns                    ; ns.example.com is a nameserver for example.com
example.com.  IN  NS    ns.somewhere.example. ; ns.somewhere.example is a backup nameserver for example.com
example.com.  IN  MX    10 mail.example.com.  ; mail.example.com is the mailserver for example.com
@             IN  MX    20 mail2.example.com. ; equivalent to above line, "@" represents zone origin
@             IN  MX    50 mail3              ; equivalent to above line, but using a relative host name
@             IN  TXT   "v=spf1 +mx -all"     ; SPF record
example.com.  IN  A     192.0.2.1             ; IPv4 address for example.com
              IN  AAAA  2001:db8:10::1        ; IPv6 address for example.com
ns            IN  A     192.0.2.2             ; IPv4 address for ns.example.com
              IN  AAAA  2001:db8:10::2        ; IPv6 address for ns.example.com
www           IN  CNAME example.com.          ; www.example.com is an alias for example.com
wwwtest       IN  CNAME www                   ; wwwtest.example.com is another alias for www.example.com
mail          IN  A     192.0.2.3             ; IPv4 address for mail.example.com
mail2         IN  A     192.0.2.4             ; IPv4 address for mail2.example.com
mail3\tIN\tA\t192.0.2.5\t; IPv4 address for mail3.example.com
"""

        try:
            r = rfcparser.RFCParser(zone)
        except rfcparser.RFCParserError as exc:  # pragma: no cover
            self.fail(
                "RFCParser() raised RFCParserError: {}".format(exc.message)
            )
        self.assertIsNotNone(r.zone)
        self.assertTrue("origin" in r.zone)
        self.assertEqual(r.zone["origin"], "example.com.")
        self.assertTrue("ttl" in r.zone)
        self.assertEqual(r.zone["ttl"], "3600")
        self.assertTrue("records" in r.zone)

        self.maxDiff = 1000
        self.assertEqual(
            [
                [
                    "example.com.",
                    "3600",
                    "SOA",
                    "ns.example.com.",
                    "username.example.com.",
                    "2007120710",
                    "1d",
                    "2h",
                    "4w",
                    "1h",
                ],
                ["example.com.", "300", "NS", "ns"],
                ["example.com.", "3600", "NS", "ns.somewhere.example."],
                ["example.com.", "3600", "MX", "10", "mail.example.com."],
                ["@", "3600", "MX", "20", "mail2.example.com."],
                ["@", "3600", "MX", "50", "mail3"],
                ["@", "3600", "TXT", '"v=spf1 +mx -all"'],
                ["example.com.", "3600", "A", "192.0.2.1"],
                ["example.com.", "3600", "AAAA", "2001:db8:10::1"],
                ["ns", "3600", "A", "192.0.2.2"],
                ["ns", "3600", "AAAA", "2001:db8:10::2"],
                ["www", "3600", "CNAME", "example.com."],
                ["wwwtest", "3600", "CNAME", "www"],
                ["mail", "3600", "A", "192.0.2.3"],
                ["mail2", "3600", "A", "192.0.2.4"],
                ["mail3", "3600", "A", "192.0.2.5"],
            ],
            r.zone["records"],
        )

    def test_rfcparser_parser_string_unclosed_quote(self):
        zone = """
$ORIGIN example.net
$TTL 86400
@       TXT     "test"test"
"""

        with self.assertRaises(rfcparser.RFCParserError) as cm:
            _ = rfcparser.RFCParser(zone)
        self.assertEqual(cm.exception.message, "Unclosed quotes")

    def test_rfcparser_parser_string_unclosed_parens(self):
        zone = """
$ORIGIN example.net
$TTL 86400
        SOA     ns.example.com. postmaster.example.com (
                86400
"""

        with self.assertRaises(rfcparser.RFCParserError) as cm:
            _ = rfcparser.RFCParser(zone)
        self.assertEqual(cm.exception.message, "Unclosed parentheses")

    def test_rfcparser_parser_string_include(self):
        zone = """
$ORIGIN example.net
$TTL 86400
$INCLUDE /tmp/example.zone
@       NS     ns.example.com.
"""

        with self.assertRaises(rfcparser.RFCParserError) as cm:
            _ = rfcparser.RFCParser(zone)
        self.assertEqual(cm.exception.message, "$INCLUDE not supported")

    def test_rfcparser_parser_string_invalid_ttl(self):
        zone = """
$ORIGIN example.net
$TTL 1h
@       NS     ns.example.com.
"""

        with self.assertRaises(rfcparser.RFCParserError) as cm:
            _ = rfcparser.RFCParser(zone)
        self.assertEqual(cm.exception.message, "Invalid TTL")

    def test_rfcparser_parser_string_missing_name(self):
        zone = """
$ORIGIN example.net
$TTL 86400
        NS     ns.example.com.
"""

        with self.assertRaises(rfcparser.RFCParserError) as cm:
            _ = rfcparser.RFCParser(zone)
        self.assertEqual(cm.exception.message, "Missing name")

    def test_rfcparser_parser_string_missing_ttl(self):
        zone = """
$ORIGIN example.net
@       NS     ns.example.com.
"""
        with self.assertRaises(rfcparser.RFCParserError) as cm:
            _ = rfcparser.RFCParser(zone)
        self.assertEqual(cm.exception.message, "Missing default TTL")

        zone = """
$ORIGIN example.net
@       IN    NS     ns.example.com.
"""
        with self.assertRaises(rfcparser.RFCParserError) as cm:
            _ = rfcparser.RFCParser(zone)
        self.assertEqual(cm.exception.message, "Missing default TTL")

    def test_rfcparser_parser_string_provided_ttl(self):
        zone = """
$ORIGIN example.net
@          86400   NS     ns1.example.com.
        IN 3600    NS     ns2.example.com.
        1800 IN    NS     ns3.example.com.
"""

        try:
            r = rfcparser.RFCParser(zone)
        except rfcparser.RFCParserError as exc:  # pragma: no cover
            self.fail(
                "RFCParser() raised RFCParserError: {}".format(exc.message)
            )

        self.assertEqual(
            [
                ["@", "86400", "NS", "ns1.example.com."],
                ["@", "3600", "NS", "ns2.example.com."],
                ["@", "1800", "NS", "ns3.example.com."],
            ],
            r.zone["records"],
        )

    def test_rfcparser_parser_string_two_ins(self):
        zone = """
$ORIGIN example.net
@       IN IN 3600 NS     ns.example.com.
"""
        with self.assertRaises(rfcparser.RFCParserError) as cm:
            _ = rfcparser.RFCParser(zone)
        self.assertEqual(cm.exception.message, "Two INs")

    def test_rfcparser_parser_string_bad_type(self):
        zone = """
$ORIGIN example.net
@       3600 IN IN NS     ns.example.com.
"""
        with self.assertRaises(rfcparser.RFCParserError) as cm:
            _ = rfcparser.RFCParser(zone)
        self.assertEqual(cm.exception.message, "Unknown or missing type")

        zone = """
$ORIGIN example.net
$TTL 3600
@       IN ZZZZ     ns.example.com.
"""
        with self.assertRaises(rfcparser.RFCParserError) as cm:
            _ = rfcparser.RFCParser(zone)
        self.assertEqual(cm.exception.message, "Unknown or missing type")

        zone = """
$ORIGIN example.net
$TTL 3600
@       ZZZZ     ns.example.com.
"""
        with self.assertRaises(rfcparser.RFCParserError) as cm:
            _ = rfcparser.RFCParser(zone)
        self.assertEqual(cm.exception.message, "Unknown or missing type")

    def test_rfcparser_parser_string_missing_origin(self):
        zone = """
$TTL 3600
@       NS     ns.example.com.
"""
        with self.assertRaises(rfcparser.RFCParserError) as cm:
            _ = rfcparser.RFCParser(zone)
        self.assertEqual(cm.exception.message, "Missing origin")

    def test_rfcparser_parser_record_method(self):
        r = rfcparser.RFCParser(self.rfc1035zone)

        self.assertEqual(
            [
                "@ 86400 MX 10 VENERA",
                "@ 86400 MX 20 VAXA",
                "A 86400 A 26.3.0.103",
                "SUB 86400 NS VAXA",
                "VENERA 86400 A 10.1.0.52",
                "VENERA 86400 A 128.9.0.32",
                "VAXA 86400 A 10.2.0.27",
                "VAXA 86400 A 128.9.0.33",
            ],
            r.records(),
        )

        self.assertEqual(
            [
                "@ 86400 SOA VENERA Action\\.domains 20 7200 600 3600000 60",
                "@ 86400 NS A.ISI.EDU.",
                "@ 86400 NS VENERA",
                "@ 86400 NS VAXA",
                "@ 86400 MX 10 VENERA",
                "@ 86400 MX 20 VAXA",
                "A 86400 A 26.3.0.103",
                "SUB 86400 NS VAXA",
                "VENERA 86400 A 10.1.0.52",
                "VENERA 86400 A 128.9.0.32",
                "VAXA 86400 A 10.2.0.27",
                "VAXA 86400 A 128.9.0.33",
            ],
            r.records(include_dangerous=True),
        )

        self.assertEqual(
            [
                "ADD @ 86400 MX 10 VENERA",
                "ADD @ 86400 MX 20 VAXA",
                "ADD A 86400 A 26.3.0.103",
                "ADD SUB 86400 NS VAXA",
                "ADD VENERA 86400 A 10.1.0.52",
                "ADD VENERA 86400 A 128.9.0.32",
                "ADD VAXA 86400 A 10.2.0.27",
                "ADD VAXA 86400 A 128.9.0.33",
            ],
            r.records(prefix="ADD"),
        )

    def test_rfcparser_parser_domain_method(self):
        r = rfcparser.RFCParser(self.rfc1035zone)
        self.assertEqual("example.net", r.domain())
