"""Devices that changed address: one device followed across its IP addresses and network cards
(MACs) from what it says about itself, addresses that changed hands, and routers left out."""
import asyncio

from anta import moves
from anta.tools import samples
from conftest import run_engine
from test_server import AUTH, make_client


def lab(tmp_path):
    path = tmp_path / "moves.pcap"
    samples.write_pcap(str(path), samples.moves_lab())

    async def go():
        dash, c = await make_client()
        try:
            dash.packets.reset(str(path))
            return await (await c.get("/api/moves", headers=AUTH)).json()
        finally:
            await c.close()
    return path, asyncio.run(go())


def test_the_lab(engine, tmp_path):
    path, d = lab(tmp_path)
    by = {x["label"]: x for x in d["devices"]}
    laptop = by["alex-laptop"]  # one network card, DHCP moved it
    assert laptop["kind"] == "moved" and laptop["verdict"] == "Same device" and len(laptop["macs"]) == 1
    c = laptop["changes"][0]
    assert (c["from_ip"], c["to_ip"]) == ("192.168.61.23", "192.168.61.41") and "DHCP gave it" in c["how"] and "back first" in c["how"]
    phone = by["Sams-Phone"]  # a new private Wi-Fi address, the same name
    assert phone["verdict"] == "Same device" and [m["randomised"] for m in phone["macs"]] == [True, True]
    assert "private Wi-Fi address" in phone["changes"][0]["how"]
    iphones = [x for x in d["devices"] if x["label"] == "iPhone"]  # (the two at once stay apart)
    assert len(iphones) == 1 and iphones[0]["verdict"] == "Probably the same device"
    assert [m["mac"] for m in iphones[0]["macs"]] == ["1e:01:02:61:00:62", "2e:03:04:61:00:63"]
    assert by["build-server"]["kind"] == "two-connections"
    assert by["nas-01"]["kind"] == "several" and by["nas-01"]["v6"] == ["fe80::211:32ff:fe61:95"]
    assert "kitchen-display" not in by and d["conflicts"][0]["name"] == "kitchen-display"
    h = d["handovers"]
    assert [x["ip"] for x in h] == ["192.168.61.70"] and [x["label"] for x in h[0]["holders"]] == ["printer-2f", "kiosk-3"]
    assert not h[0]["at_once"] and d["routers"] == ["00:0c:29:61:00:01"]
    assert d["totals"]["moved"] == 3 and d["totals"]["new_mac"] == 2 and d["start"] < d["end"]
    out = run_engine(engine, "--packets", "-r", str(path), "-Y", phone["filter"])
    assert {r["src"] for r in out if r.get("type") == "packet"} >= {"192.168.61.50", "192.168.61.51"}


def mac(m, spans, arp=(), src=None):
    return {"mac": m, "vendor": "", "src_ips": src or [s[0] for s in spans], "arp_ips": list(arp), "ip_spans": spans}


def test_routers_and_forwarded_addresses():
    stats = {"hosts": [], "macs": [
        # Addresses from several networks, none announced: forwarding between them.
        mac("00:0c:29:00:00:01", [["192.168.1.5", 0, 10], ["192.168.2.7", 20, 30]]),
        # Its own address announced in ARP; the other network's address is forwarded traffic.
        mac("00:0c:29:00:00:02", [["192.168.3.1", 0, 100], ["192.168.4.9", 0, 5], ["192.168.4.9", 50, 60]], arp=["192.168.3.1"]),
        # One network, one card, two addresses one after the other.
        mac("00:0c:29:00:00:03", [["10.0.0.5", 0, 10], ["10.0.0.9", 20, 30]]),
        mac("01:00:5e:00:00:fb", [["10.0.0.5", 0, 1]]),  # (a group address: never a device)
    ]}
    r = moves.link(stats, [])
    assert r["routers"] == ["00:0c:29:00:00:01"]
    moved = [x for x in r["devices"] if x["kind"] == "moved"]
    assert [x["macs"][0]["mac"] for x in moved] == ["00:0c:29:00:00:03"] and moved[0]["changes"][0]["to_ip"] == "10.0.0.9"


def dhcp(ts, m, name, vendor="", prl=(1, 3, 6), mtype=3):
    f = {"dhcp.option.dhcp": [str(mtype)], "dhcp.hw.mac_addr": [m], "dhcp.option.hostname": [name],
         "dhcp.option.request_list_item": [str(x) for x in prl]}
    if vendor:
        f["dhcp.option.vendor_class_id"] = [vendor]
    return {"type": "packet", "ts": ts, "f": f}


def test_a_common_name_with_two_candidates_links_nothing():
    stats = {"hosts": [], "macs": [mac("12:00:00:00:00:01", [["10.0.0.5", 0, 10]]), mac("16:00:00:00:00:02", [["10.0.0.6", 20, 30]]),
                                   mac("1a:00:00:00:00:03", [["10.0.0.7", 25, 40]])]}
    rows = [dhcp(0, "12:00:00:00:00:01", "iPhone"), dhcp(20, "16:00:00:00:00:02", "iPhone"), dhcp(25, "1a:00:00:00:00:03", "iPhone")]
    assert not [x for x in moves.link(stats, rows)["devices"] if len(x["macs"]) > 1]
    # A specific name links them all, whichever system each request came from as long as they agree.
    rows = [dhcp(0, "12:00:00:00:00:01", "lab-pc-7"), dhcp(20, "16:00:00:00:00:02", "LAB-PC-7.local")]
    r = moves.link(stats, rows)
    assert [len(x["macs"]) for x in r["devices"] if x["kind"] == "moved"] == [2]


def test_names_from_mdns_and_netbios():
    stats = {"hosts": [{"addr": "10.0.0.5", "names": [["studio-mac.local", "mDNS"]]},
                       {"addr": "10.0.0.6", "names": [["STUDIO-MAC", "NetBIOS"]]}],
             "macs": [mac("3c:00:00:00:00:01", [["10.0.0.5", 0, 10]]), mac("3e:00:00:00:00:02", [["10.0.0.6", 20, 30]])]}
    dv = next(x for x in moves.link(stats, [])["devices"] if x["kind"] == "moved")
    assert dv["verdict"] == "Same device" and "mDNS" in dv["why"][0] and "NetBIOS" in dv["why"][0]


def test_randomised_macs():
    assert moves.randomised("da:a1:19:00:00:01") and moves.randomised("02:00:00:00:00:01")
    assert not moves.randomised("3c:22:fb:61:00:23") and not moves.randomised("nonsense")
