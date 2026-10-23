import time

from app.netscope import Scope, parse_ranges


def _scope(**routers):
    s = Scope()
    s.ts = time.time() + 10 ** 9           # no DB refresh
    s.internal, _ = parse_ranges("10.0.0.0/8\n172.16.0.0/12\n192.168.0.0/16")
    s.internet, _ = parse_ranges("10.1.1.250  # proxy")
    for rid, (lan, wan) in routers.items():
        s.routers[int(rid[1:])] = {"lan": parse_ranges(lan)[0], "wan": wan}
        s.by_ip[f"192.0.2.{rid[1:]}"] = int(rid[1:])
        s._resolve(int(rid[1:]))
    return s


def test_parse_ranges():
    nets, bad = parse_ranges("10.0.0.0/8, 192.168.1.5\n172.16.0.10-172.16.0.20 # comment\nfoo 300.1.1.1/24")
    assert [str(n) for n in nets[:2]] == ["10.0.0.0/8", "192.168.1.5/32"]
    assert sum(n.num_addresses for n in nets[2:]) == 11
    assert bad == ["foo", "300.1.1.1/24"]


def test_ranges_only():
    s = _scope(r1=("", []))
    assert s.is_internal("192.0.2.1", "192.168.5.9")
    assert not s.is_internal("192.0.2.1", "8.8.8.8")
    assert not s.is_internal("192.0.2.1", "10.1.1.250")      # exception: proxy = internet


def test_wan_interfaces_and_router_ranges():
    s = _scope(r1=("203.0.113.0/24", ["ether1", "5"]))
    s.learn(1, [{".id": "*1", "name": "ether1"}, {".id": "*A", "name": "bridge"}], [{"address": "198.51.100.1/24"}])
    assert s.routers[1]["wan_idx"] == {1, 5}
    assert not s.is_internal("192.0.2.1", "8.8.8.8", 1, 10)     # in from WAN
    assert not s.is_internal("192.0.2.1", "192.168.1.1", 10, 5)  # private, but out via WAN (ISP modem)
    assert s.is_internal("192.0.2.1", "8.8.8.8", 10, 11)        # LAN -> LAN
    assert s.is_internal("192.0.2.1", "203.0.113.7", 1, 10)     # router's own internal range wins
    assert s.is_internal("192.0.2.1", "192.168.1.1")            # no interface info -> ranges
    # exporter found by the router's own address learned over API
    assert s.router_id("198.51.100.1") == 1
