import socket
import struct

from app.netflow import TemplateParser


def _ipfix(sets):
    body = b"".join(sets)
    return struct.pack("!HHIII", 10, 16 + len(body), 0, 1, 0) + body


def test_ipfix_post_nat():
    fields = [(1, 8), (4, 1), (7, 2), (8, 4), (11, 2), (12, 4), (225, 4), (226, 4)]
    tpl = struct.pack("!HH", 256, len(fields)) + b"".join(struct.pack("!HH", t, l) for t, l in fields)
    tpl_set = struct.pack("!HH", 2, 4 + len(tpl)) + tpl
    # download: remote 1.1.1.1:443 -> router public 5.5.5.5:40000, post-NAT dst = 10.5.50.10
    rec = (struct.pack("!QBH", 123456, 6, 443) + socket.inet_aton("1.1.1.1") + struct.pack("!H", 40000) +
           socket.inet_aton("5.5.5.5") + socket.inet_aton("1.1.1.1") + socket.inet_aton("10.5.50.10"))
    data_set = struct.pack("!HH", 256, 4 + len(rec)) + rec
    p = TemplateParser()
    assert p.parse(_ipfix([tpl_set]), "r1") == []
    flows = p.parse(_ipfix([data_set]), "r1")
    assert flows == [{"src": "1.1.1.1", "dst": "5.5.5.5", "sport": 443, "dport": 40000, "proto": 6,
                      "bytes": 123456, "post_src": "1.1.1.1", "post_dst": "10.5.50.10",
                      "in_if": 0, "out_if": 0}]
