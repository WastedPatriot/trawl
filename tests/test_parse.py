import pytest

from trawl.parse import parse_ffuf_json, parse_nmap_xml, parse_nuclei_jsonl


def test_nmap_keeps_open_ports_and_knows_https(fixtures):
    hosts = parse_nmap_xml((fixtures / "nmap_basic.xml").read_text())
    assert len(hosts) == 1
    host = hosts[0]
    assert host.address == "10.10.11.42"
    assert host.label == "storage.htb"
    assert host.status == "up"
    ports = {port.port: port for port in host.ports}
    assert sorted(ports) == [22, 80, 443, 8080]
    assert ports[22].is_http is False
    assert ports[80].scheme == "http"
    assert ports[443].scheme == "https"
    assert ports[443].service_label == "https"
    assert "nginx" in ports[80].version_label
    assert ports[80].scripts[0][0] == "http-title"
    assert "Storage" in ports[80].scripts[0][1]
    assert "\n" not in ports[80].scripts[0][1]


def test_nmap_down_host_has_no_ports(fixtures):
    hosts = parse_nmap_xml((fixtures / "nmap_down.xml").read_text())
    assert hosts[0].status == "down"
    assert hosts[0].ports == []
    assert hosts[0].address == "10.10.11.99"


def test_nmap_rejects_broken_xml():
    with pytest.raises(ValueError):
        parse_nmap_xml("<nmaprun><host></nmaprun>")


def test_ffuf_results_sorted_and_missing_fields_tolerated(fixtures):
    hits = parse_ffuf_json((fixtures / "ffuf_basic.json").read_text())
    assert [hit.status for hit in hits] == [200, 301, 401]
    by_status = {hit.status: hit for hit in hits}
    assert by_status[200].fuzz == ".git/HEAD"
    assert by_status[301].content_type == ""
    assert by_status[401].url.endswith("/admin")


def test_ffuf_empty_and_blank(fixtures):
    assert parse_ffuf_json((fixtures / "ffuf_empty.json").read_text()) == []
    assert parse_ffuf_json("   ") == []
    assert parse_ffuf_json("null") == []


def test_ffuf_rejects_broken_json():
    with pytest.raises(ValueError):
        parse_ffuf_json("{not json")


def test_nuclei_skips_junk_and_reads_string_tags(fixtures):
    findings = parse_nuclei_jsonl((fixtures / "nuclei_basic.jsonl").read_text())
    assert [item.severity for item in findings] == ["medium", "high", "info"]
    assert findings[0].template_id == "git-config"
    assert findings[0].matched_at.endswith("/.git/config")
    assert findings[1].tags == ["apache", "tech"]
    assert "2.4.49" in findings[1].description


def test_nuclei_accepts_legacy_template_key():
    raw = '{"templateID":"old-id","info":{"name":"Old","severity":"low"},"matched":"http://x"}'
    found = parse_nuclei_jsonl(raw)
    assert found[0].template_id == "old-id"
    assert found[0].matched_at == "http://x"
    assert found[0].severity == "low"
