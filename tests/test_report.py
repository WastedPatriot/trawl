from trawl.models import Host, Port, ScanReport
from trawl.parse import parse_ffuf_json, parse_nmap_xml, parse_nuclei_jsonl
from trawl.report import quiet_lines, render_html, render_markdown, write_reports


def _sample(fixtures) -> ScanReport:
    hosts = parse_nmap_xml((fixtures / "nmap_basic.xml").read_text())
    hosts[0].ports[0].version = "<script>alert(1)</script>"
    report = ScanReport(targets=["10.10.11.42"])
    report.hosts = hosts
    report.web = parse_ffuf_json((fixtures / "ffuf_basic.json").read_text())
    report.findings = parse_nuclei_jsonl((fixtures / "nuclei_basic.jsonl").read_text())
    report.counts = {"nmap": 4, "ffuf": 3, "nuclei": 3}
    return report


def test_reports_escape_tool_output_and_order_severity(fixtures):
    report = _sample(fixtures)
    markdown = render_markdown(report, when="2026-11-11 12:00 UTC", version="0.1.0")
    page = render_html(report, when="2026-11-11 12:00 UTC", version="0.1.0")
    assert "<script>" not in page
    assert "&lt;script&gt;" in page
    assert "<script" not in markdown
    assert "storage.htb" in markdown
    assert "http-title" in markdown
    assert page.index("sev high") < page.index("sev medium")
    assert "googleapis" not in page
    assert 'rel="noreferrer"' in page
    assert "<!-- tight lines -->" in page
    assert "<!-- tight lines -->" in markdown


def test_empty_report_has_one_quiet_line():
    report = ScanReport(targets=["10.10.11.99"])
    report.counts = {"nmap": 0, "ffuf": 0}
    text = render_markdown(report, when="t", version="0.1.0")
    page = render_html(report, when="t", version="0.1.0")
    assert text.count("nothing in the nets today") == 1
    assert "nothing in the nets today" in page
    assert "http://" not in page
    assert quiet_lines(report) == ["nothing in the nets today"]


def test_a_quiet_tool_is_named_when_the_rest_found_something():
    report = ScanReport(targets=["10.10.11.42"])
    report.hosts = [
        Host(
            address="10.10.11.42",
            ports=[Port(port=22, protocol="tcp", state="open", service="ssh")],
        )
    ]
    report.counts = {"nmap": 1, "ffuf": 0}
    assert quiet_lines(report) == ["ffuf: nothing in the nets today"]


def test_write_reports_creates_both_files(tmp_path, fixtures):
    markdown, page = write_reports(tmp_path, _sample(fixtures), when="2026-11-11 12:00 UTC")
    assert markdown.name == "report.md"
    assert page.name == "report.html"
    assert "Authorised targets only." in markdown.read_text()
    assert page.read_text().startswith("<!DOCTYPE html>")
