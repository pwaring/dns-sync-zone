import zone_validate


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
        elif isinstance(source, str):
            self.zone = self.parse_from_string(source)
        else:
            try:
                self.zone = self.parse_from_string(source.read())
            except AttributeError:
                raise RFCParserError(
                    "Argument is neither string nor file object"
                )

    @staticmethod
    def is_valid_ttl(ttl):
        return zone_validate.is_valid_ttl(ttl)

    @staticmethod
    def is_valid_type(name):
        """Check that type name is valid"""
        return _valid_types.get(name.upper(), False)

    def parse_from_string(self, string):
        lines = string.splitlines()
        tokenized = []

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

        # Parse RR lines
        rr = []
        default_ttl = None
        for tokens in records:
            line = " ".join(tokens)
            name = tokens.pop(0)
            if name.upper() == "$ORIGIN":
                origin = tokens.pop(0)
                if not origin.endswith("."):
                    origin += "."
                zone["origin"] = origin
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

    def records(self, prefix=None, include_dangerous=False):
        ret = []
        origins = ["@"]
        if self.zone["origin"]:
            origin = self.zone["origin"]
            origins.append(origin)

        for rr in self.zone["records"]:
            dangerous = False
            if rr[2] == "SOA":
                dangerous = True
            elif rr[2] == "NS" and rr[0] in origins:
                dangerous = True

            if not dangerous or include_dangerous:
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
