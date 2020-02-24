import sys
import re


#
# These can be obtained from
# https://www.iana.org/assignments/dns-parameters/dns-parameters-4.csv
#
_valid_types = {
    t: True
    for t in [
        "A",
        "NS",
        "CNAME",
        "SOA",
        "WKS",
        "PTR",
        "HINFO",
        "MINFO",
        "MX",
        "TXT",
        "RP",
        "AFSDB",
        "X25",
        "ISDN",
        "RT",
        "NSAP",
        "NSAP-PTR",
        "SIG",
        "KEY",
        "PX",
        "GPOS",
        "AAAA",
        "LOC",
        "EID",
        "NIMLOC",
        "SRV",
        "ATMA",
        "NAPTR",
        "KX",
        "CERT",
        "DNAME",
        "SINK",
        "OPT",
        "APL",
        "DS",
        "SSHFP",
        "IPSECKEY",
        "RRSIG",
        "NSEC",
        "DNSKEY",
        "DHCID",
        "NSEC3",
        "NSEC3PARAM",
        "TLSA",
        "SMIMEA",
        "HIP",
        "NINFO",
        "RKEY",
        "TALINK",
        "CDS",
        "CDNSKEY",
        "OPENPGPKEY",
        "CSYNC",
        "ZONEMD",
        "SPF",
        "UINFO",
        "UID",
        "GID",
        "UNSPEC",
        "NID",
        "L32",
        "L64",
        "LP",
        "EUI48",
        "EUI64",
        "TKEY",
        "TSIG",
        "IXFR",
        "AXFR",
        "MAILB",
        "URI",
        "CAA",
        "AVC",
        "DOA",
        "AMTRELAY",
        "TA",
        # Extra
        "ANAME",
    ]
}


class RFCParserError(Exception):
    """Class for exceptions"""

    def __init__(self, message, line=None):
        self.message = message
        self.line = line


class RFCParser(object):
    """Parser for RFC 1035/Bind format zonefiles

    """

    def __init__(self, source=None):
        if source is None:
            self.zone = None
        if isinstance(source, str):
            self.zone = self.parse_from_string(source)
        else:
            try:
                self.zone = self.parse_from_string(source.read())
            except AttributeError:
                raise RFCParserError(
                    "Argument is neither string nor file object"
                )
                print("", file=sys.stderror)
                raise

    @staticmethod
    def is_valid_ttl(ttl):
        """Check that ttl value is valid (ie. positive signed 32 bit number)"""
        if len(ttl) == 0:
            return False
        match = re.search(r"[^0-9]", ttl)
        if match is not None:
            return False
        value = int(ttl)
        if not (0 <= value < 2 ** 31):
            return False
        return True

    @staticmethod
    def is_valid_type(name):
        """Check that type name is valid"""
        return _valid_types.get(name.upper(), False)

    def parse_from_string(self, string):
        lines = string.splitlines()
        tokenized = list()

        # tokenize, honouring quoted strings, and strip comments
        for line in lines:
            tokens = []
            tok = ""
            quoted = False
            for c in line:
                if quoted:
                    tok += c
                    if c == '"':
                        quoted = False
                elif c in [" ", "\t"]:
                    if len(tok) > 0:
                        tokens.append(tok)
                        tok = ""
                    elif len(tokens) == 0:
                        tokens.append("")
                else:
                    if c == '"':
                        quoted = True
                    if c == ";":
                        break
                    tok += c
            if quoted:
                raise RFCParserError("Unclosed quotes", line)
            if tok:
                tokens.append(tok)
            if tokens:
                tokenized.append(tokens)

        zone = dict(origin=None, ttl=None, records=None)

        # concatenate continuation lines
        records = []
        r = []
        continuation = False
        previous_name = None
        for tokens in tokenized:
            for token in tokens:
                t = token
                if continuation:
                    if token.endswith(")"):
                        continuation = False
                        t = t[:-1]
                else:
                    if token.startswith("("):
                        continuation = True
                        t = t[1:]
                if r and t:
                    r.append(t)
                elif len(r) == 0:
                    r.append(t)
            if not continuation:
                records.append(r)
                r = []
        if continuation:
            raise RFCParserError("Unclosed parentheses")
        else:
            if r:
                records.append(r)

        # Parse RR lines
        rr = []
        default_ttl = None
        for tokens in records:
            line = " ".join(tokens)
            name = tokens.pop(0)
            if name.upper() == "$ORIGIN":
                zone["origin"] = tokens.pop(0)
            elif name.upper() == "$INCLUDE":
                raise RFCParserError("$INCLUDE not supported")
            elif name.upper() == "$TTL":
                ttl = tokens.pop(0)
                if self.is_valid_ttl(ttl):
                    zone["ttl"] = ttl
                    default_ttl = ttl
                else:
                    raise RFCParserError("Invalid TTL", line)
            else:
                if name == "":
                    name = previous_name
                else:
                    previous_name = name
                if name == "" or name is None:
                    raise RFCParserError("Missing name", line)
                t = [name]
                next = tokens.pop(0)
                # class and TTL are both optional, and may occur in any order
                if next.upper() == "IN":
                    # ignore default "IN" class
                    next = tokens.pop(0)
                    if next.upper() == "IN":
                        raise RFCParserError("Two INs", line)
                    if self.is_valid_ttl(next):
                        t.append(next)
                    elif self.is_valid_type(next):
                        if default_ttl is None:
                            raise RFCParserError("Missing default TTL", line)
                        t.append(default_ttl)
                        t.append(next)
                    else:
                        raise RFCParserError("Unknown or missing type", line)
                elif self.is_valid_ttl(next):
                    t.append(next)
                    next = tokens.pop(0)
                    if next.upper() == "IN":
                        # ignore default "IN" class
                        pass
                    elif self.is_valid_type(next):
                        t.append(next)
                    else:
                        raise RFCParserError("Unknown or missing type", line)
                elif self.is_valid_type(next):
                    if default_ttl is None:
                        raise RFCParserError("Missing default TTL", line)
                    t.append(default_ttl)
                    t.append(next)
                else:
                    raise RFCParserError("Unknown or missing type", line)

                t.extend(tokens)
                rr.append(t)

        zone["records"] = rr

        if zone["origin"] is None:
            raise RFCParserError("Missing origin")

        return zone

    def records(self, prefix=None):
        ret = []
        for rr in self.zone["records"]:
            if rr[2] in ["SOA", "NS"]:
                pass
            else:
                line = " ".join(rr)
                if prefix:
                    line = "{} {}".format(prefix, line)
                ret.append(line)
        return ret

    def domain(self):
        d = self.zone["origin"]
        if d.endswith("."):
            d = d[:-1]
        return d


def tryzone(s):
    try:
        z = RFCParser(s)
    except RFCParserError as err:
        if err.line:
            print(f"Error: {err.message} in {err.line}")
        else:
            print(f"Error: {err.message}")
    else:
        import pprint

        pprint.pprint(z.records("ADD"))
        breakpoint()


def main():
    # test code with classic example from RFC1035

    tryzone(
        """
@   IN  SOA     VENERA      Action\.domains (
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

VENERA  A       10.1.0.52
        A       128.9.0.32

VAXA    A       10.2.0.27
        A       128.9.0.33
"""
    )

    tryzone(
        """
$ORIGIN example.com.     ; designates the start of this zone file in the namespace
$TTL 3600                ; default expiration time of all resource records without their own TTL value
example.com.  IN  SOA   ns.example.com. username.example.com. ( 2007120710 1d 2h 4w 1h )
example.com.  IN  300 NS    ns                    ; ns.example.com is a nameserver for example.com
example.com.  IN  NS    ns.somewhere.example. ; ns.somewhere.example is a backup nameserver for example.com
example.com.  IN  MX    10 mail.example.com.  ; mail.example.com is the mailserver for example.com
@             IN  MX    20 mail2.example.com. ; equivalent to above line, "@" represents zone origin
@             IN  MX    50 mail3              ; equivalent to above line, but using a relative host name
example.com.  IN  A     192.0.2.1             ; IPv4 address for example.com
              IN  AAAA  2001:db8:10::1        ; IPv6 address for example.com
ns            IN  A     192.0.2.2             ; IPv4 address for ns.example.com
              IN  AAAA  2001:db8:10::2        ; IPv6 address for ns.example.com
www           IN  CNAME example.com.          ; www.example.com is an alias for example.com
wwwtest       IN  CNAME www                   ; wwwtest.example.com is another alias for www.example.com
mail          IN  A     192.0.2.3             ; IPv4 address for mail.example.com
mail2         IN  A     192.0.2.4             ; IPv4 address for mail2.example.com
mail3         IN  A     192.0.2.5             ; IPv4 address for mail3.example.com
"""
    )

    with open("/tmp/codethink.co.uk") as f:
        tryzone(f)


if __name__ == "__main__":
    main()
