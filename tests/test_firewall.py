"""The firewall dry run: rules in plain words, iptables, ufw, pf or Cisco access lists, replayed
against a capture's connections, statefully, at the border or on every device."""
import pytest

from anta import firewall as fw


def S(src, dst, dport, proto="tcp", up=100, sport=50000):
    return {"proto": proto, "src_ip": src, "dst_ip": dst, "src_port": sport, "dst_port": dport,
            "c2s": {"payload_bytes": up}, "s2c": {"payload_bytes": 100}}


SESSIONS = [
    S("10.0.0.5", "8.8.8.8", 443),            # out: web
    S("10.0.0.5", "8.8.4.4", 25),             # out: mail
    S("203.0.113.9", "10.0.0.7", 22),         # in: ssh from the internet
    S("203.0.113.9", "10.0.0.7", 3389),       # in: remote desktop
    S("10.0.0.5", "10.0.0.60", 631),          # inside: printing
    S("10.0.0.5", "10.0.0.1", 53, "udp"),     # inside: dns
    {"proto": "other", "src_ip": "10.0.0.5", "dst_ip": "8.8.8.8"},
]


@pytest.mark.parametrize("line, reads", [
    ("block in tcp to any port 23", "Block TCP coming in on port 23"),
    ("allow out to the internet port 443", "Allow connections going out to the internet on port 443"),
    ("block from 10.0.0.0/24 to the local network port 631",
     "Block connections from 10.0.0.0/24 to the local network on port 631"),
    ("iptables -A INPUT -p tcp -s 10.0.0.0/8 --dport 22 -j ACCEPT", "Allow TCP coming in from 10.0.0.0/8 on port 22 (IPv4 only)"),
    ("-A FORWARD -p tcp -m multiport --dports 445,139 -j DROP", "Block TCP on port 445, 139"),
    ("ufw deny 23/tcp", "Block TCP coming in on port 23"),
    ("ufw allow from 10.0.0.0/24 to any port ssh", "Allow connections coming in from 10.0.0.0/24 on port 22"),
    ("block in quick proto tcp from any to any port {22 3389}", "Block TCP coming in on port 22, 3389 (stops here: quick)"),
    ("access-list 101 deny tcp host 10.0.0.5 any range 1000 2000", "Block TCP from 10.0.0.5 on port 1000-2000"),
    ("access-list 101 permit ip 10.0.0.0 0.0.0.255 any", "Allow connections from 10.0.0.0/24"),
    ("10 deny tcp any any eq telnet", "Block TCP on port 23"),
])
def test_every_syntax_reads_back(line, reads):
    p = fw.parse(line)
    assert not p["errors"] and p["rules"][0].reads() == reads


@pytest.mark.parametrize("line", ["nonsense here", "iptables -A INPUT -j MYCHAIN", "block from <bad> to any",
                                  "iptables -A INPUT ! -s 1.2.3.4 -j DROP", "iptables -A INPUT -m state --state ESTABLISHED -j ACCEPT",
                                  "allow in to any port 99999", "ufw limit ssh"])
def test_what_cant_be_judged_says_why(line):
    p = fw.parse(line)
    assert not p["rules"] and p["errors"][0]["line"] == 1 and p["errors"][0]["error"]


def test_at_the_border():
    r = fw.run("block in tcp to any port 22\nblock out to any port 25", SESSIONS, placement="border")
    t = r["totals"]
    assert (t["connections"], t["blocked"], t["unseen"], t["not_judged"]) == (4, 2, 2, 1)  # (printing and DNS stay inside)
    assert {g["what"] for g in r["blocked"]} == {"203.0.113.9 → 10.0.0.7:22 (SSH)", "10.0.0.5 → 8.8.4.4:25 (email (SMTP))"}
    assert [x["hits"] for x in r["rules"]] == [1, 1] and r["blocked"][0]["by"].startswith("line ")


def test_on_every_device_inside_traffic_counts():
    r = fw.run("block udp to any port 53", SESSIONS, placement="host")
    assert r["totals"]["blocked"] == 1 and r["breaks"][0]["service"] == "DNS" and r["breaks"][0]["devices"] == 2


def test_defaults_and_matching_orders():
    # iptables: a chain's policy decides what no rule matches.
    r = fw.run("iptables -A INPUT -p tcp --dport 22 -j ACCEPT\niptables -P INPUT DROP", SESSIONS)
    assert {g["what"].split(":")[1] for g in r["blocked"]} == {"3389 (Remote Desktop)"}
    assert r["defaults"]["in"]["action"] == "block"
    # ufw: incoming is denied by default once it says so.
    assert fw.run("ufw default deny incoming\nufw allow 22/tcp", SESSIONS)["totals"]["blocked"] == 1
    # First match wins...
    assert fw.run("allow in to any port 22\nblock in to any", SESSIONS)["totals"]["blocked"] == 1
    # ...but pf's last match wins, unless a quick rule matched first.
    assert fw.run("pass in proto tcp to any port 22\nblock in all", SESSIONS)["totals"]["blocked"] == 2
    assert fw.run("pass in quick proto tcp to any port 22\nblock in all", SESSIONS)["totals"]["blocked"] == 1
    # A Cisco list ends with an invisible deny any.
    r = fw.run("access-list 101 deny tcp any any eq 23", SESSIONS)
    assert r["totals"]["blocked"] == 4 and "implicit" in r["defaults"]["out"]["why"]
    assert fw.run("access-list 101 deny tcp any any eq 23\naccess-list 101 permit ip any any", SESSIONS)["totals"]["blocked"] == 0


def test_alerts_stopped_still_through_or_inside():
    alerts = [{"id": "A1", "title": "C2 Beaconing", "severity": "critical", "src_ip": "10.0.0.5", "dst_ip": "8.8.4.4",
               "dst_port": 25},
              {"id": "A2", "title": "Exfil", "severity": "high", "src_ip": "10.0.0.5", "dst_ip": "8.8.8.8", "dst_port": 443},
              {"id": "A3", "title": "Odd DNS", "severity": "high", "src_ip": "10.0.0.5", "dst_ip": "10.0.0.1", "dst_port": 53},
              {"id": "A4", "title": "Dismissed", "severity": "high", "src_ip": "10.0.0.5", "dst_ip": "8.8.8.8", "dst_port": 443,
               "triage": {"status": "false_positive"}}]
    al = fw.run("block out to any port 25", SESSIONS, alerts)["alerts"]
    assert [a["id"] for a in al["stopped"]] == ["A1"] and [a["id"] for a in al["through"]] == ["A2"]
    assert [a["id"] for a in al["inside"]] == ["A3"]


def test_bad_placement():
    with pytest.raises(fw.FirewallError):
        fw.run("block in to any", SESSIONS, placement="space")
