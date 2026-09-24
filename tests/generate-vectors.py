"""Generate tests/vectors.json from Python's ipaddress module.

ipaddress is the independent reference: it decides what an address expands to
and what its canonical compressed form is (RFC 5952), and ipv6-classify has to
agree. Nothing here is hand-written except the list of addresses.

    python tests/generate-vectors.py           # rewrite vectors.json
    python tests/generate-vectors.py --check   # fail if the committed file drifted
"""
import ipaddress
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).parent
OUT = HERE / "vectors.json"

VALID = [
    # the specials
    "::",
    "::1",
    # NOTE: IPv4-mapped addresses (::ffff:1.2.3.4) are deliberately NOT here.
    # Python only began rendering them with a dotted tail partway through the
    # 3.12 series, so str() gives "::ffff:c0a8:1" on one patch release and
    # "::ffff:192.168.0.1" on another. A reference that disagrees with itself
    # cannot arbitrate, so RFC 5952 section 5 decides and tests/run.js asserts
    # the dotted form by hand.
    # link-local and unique-local
    "fe80::1",
    "fe80::0202:b3ff:fe1e:8329",
    "fc00::1",
    "fd12:3456:789a:1::1",
    # multicast
    "ff02::1",
    "ff05::1:3",
    # global unicast
    "2606:4700:4700::1111",
    "2001:4860:4860::8888",
    "2a00:1450:4001:80e::200e",
    "2400:cb00:2048:1::c629:d7a2",
    # tunnels and reserved
    "2002:c000:204::",
    "2001:0:4136:e378:8000:63bf:3fff:fdd2",
    "2001:db8::1",
    "2001:db8:0:0:1:0:0:1",
    # compression edge cases: two equal runs, leading run, trailing run
    "1:0:0:2:0:0:0:3",
    "0:0:1:2:3:4:5:6",
    "1:2:3:4:5:6:0:0",
    "1:0:2:0:3:0:4:0",
    "2001:db8:0:1:1:1:1:1",
    # full form, nothing to compress
    "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
    # EUI-64 shapes
    "2001:db8::0212:34ff:fe56:7890",
    "fe80::021b:63ff:fe98:7654",
]

INVALID = [
    "",
    "1.2.3.4",
    "not an address",
    ":::",
    "1::2::3",
    "12345::1",
    "2001:db8:::1",
    "gggg::1",
    "1:2:3:4:5:6:7",
    "1:2:3:4:5:6:7:8:9",
    "::ffff:999.1.1.1",
    "::ffff:1.2.3",
]


def build():
    valid = []
    for a in VALID:
        ip = ipaddress.IPv6Address(a)
        # ONLY the stable facts. The is_private / is_global properties are
        # deliberately not recorded: their definitions changed within the 3.12
        # series (the CVE-2024-4032 fix), so committing them pins the vectors
        # to one patch release and CI fails on another. Expansion and RFC 5952
        # compression are pure formatting and do not drift.
        valid.append({
            "input": a,
            "exploded": ip.exploded,          # "0000:0000:...:0001"
            "compressed": str(ip),            # RFC 5952 canonical form
        })

    invalid = []
    for a in INVALID:
        try:
            ipaddress.IPv6Address(a)
        except ValueError:
            invalid.append(a)
        else:
            raise SystemExit(
                "%r is actually valid according to ipaddress - "
                "remove it from INVALID" % a
            )

    return {"valid": valid, "invalid": invalid}


def main():
    data = build()
    text = json.dumps(data, indent=2, sort_keys=True) + "\n"

    if "--check" in sys.argv:
        if not OUT.exists():
            raise SystemExit("vectors.json is missing - run without --check")
        current = OUT.read_text(encoding="utf-8")
        if current != text:
            raise SystemExit(
                "vectors.json does not match what ipaddress produces now.\n"
                "Run: python tests/generate-vectors.py"
            )
        print("vectors.json matches Python's ipaddress (%d valid, %d invalid)"
              % (len(data["valid"]), len(data["invalid"])))
        return

    OUT.write_text(text, encoding="utf-8", newline="\n")
    print("wrote %s (%d valid, %d invalid)"
          % (OUT.name, len(data["valid"]), len(data["invalid"])))


main()
