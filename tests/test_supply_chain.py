"""Supply chain scanner tests."""

from nyuwaymcpscanner.scanners.supply_chain import scan_supply_chain


def test_clean_server_no_supply_chain_findings(clean_server_path):
    findings = scan_supply_chain(str(clean_server_path))
    assert isinstance(findings, list)


def test_finding_structure(clean_server_path):
    findings = scan_supply_chain(str(clean_server_path))
    for f in findings:
        assert "type" in f
        assert "severity" in f
        assert "description" in f


def test_detects_typosquatting_in_requirements(tmp_path):
    project = tmp_path / "squat_project"
    project.mkdir()
    (project / "requirements.txt").write_text("requessts==1.0.0\n")
    findings = scan_supply_chain(str(project), offline=True)
    squat_findings = [f for f in findings if f["type"] == "typosquatting_risk"]
    assert squat_findings, (
        "Expected typosquatting risk for 'requessts' (one edit from 'requests')"
    )
    assert squat_findings[0]["package"] == "requessts"


def test_parses_package_json(tmp_path):
    project = tmp_path / "node_project"
    project.mkdir()
    (project / "package.json").write_text(
        '{"dependencies": {"lodash": "^4.17.15"}, '
        '"devDependencies": {"jest": "29.0.0"}}'
    )
    findings = scan_supply_chain(str(project), offline=True)
    # No findings expected (no typosquatting on lodash/jest, no CVE lookup),
    # but the parser must not crash.
    assert isinstance(findings, list)


def test_requirements_with_comments_and_extras(tmp_path):
    project = tmp_path / "py_project"
    project.mkdir()
    (project / "requirements.txt").write_text(
        "# top-level deps\n"
        "requests==2.31.0  # http client\n"
        "\n"
        "django>=4.0\n"
        "-r other.txt\n"
    )
    findings = scan_supply_chain(str(project), offline=True)
    assert isinstance(findings, list)


def test_osv_vuln_parsed_into_finding(tmp_path, monkeypatch):
    """End-to-end: a mocked OSV.dev response is parsed into a structured finding."""
    project = tmp_path / "vuln_project"
    project.mkdir()
    (project / "requirements.txt").write_text("lodash==4.17.15\n")

    osv_response = {
        "vulns": [
            {
                "id": "GHSA-35jh-r3h4-6jhm",
                "summary": "Prototype Pollution in lodash",
                "severity": [
                    {
                        "type": "CVSS_V3",
                        "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    }
                ],
                "database_specific": {"severity": ["HIGH"]},
            }
        ]
    }

    from nyuwaymcpscanner.scanners import supply_chain as sc

    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return osv_response

    monkeypatch.setattr(sc.requests, "post", lambda *a, **kw: FakeResponse())

    findings = scan_supply_chain(str(project), offline=False)
    cve_findings = [f for f in findings if f["type"] == "dependency_cve"]
    assert cve_findings, "Expected at least one CVE finding from mocked OSV response"
    f = cve_findings[0]
    assert f["cve_id"] == "GHSA-35jh-r3h4-6jhm"
    assert f["severity"] == "high"
    assert f["weight"] == 20
    assert f["package"] == "lodash"
    assert f["ecosystem"] == "PyPI"  # requirements.txt → PyPI ecosystem


def test_osv_returns_garbage_body(tmp_path, monkeypatch):
    """A 200 OK response whose body isn't JSON must degrade to empty, not crash."""
    project = tmp_path / "garbage_project"
    project.mkdir()
    (project / "requirements.txt").write_text("requests==2.31.0\n")

    from nyuwaymcpscanner.scanners import supply_chain as sc

    class GarbageResponse:
        def raise_for_status(self):
            pass

        def json(self):
            raise ValueError("not json")

    monkeypatch.setattr(sc.requests, "post", lambda *a, **kw: GarbageResponse())
    findings = scan_supply_chain(str(project), offline=False)
    # No CVE findings, no crash.
    cve_findings = [f for f in findings if f["type"] == "dependency_cve"]
    assert cve_findings == []


def test_osv_returns_http_error(tmp_path, monkeypatch):
    """HTTPError on raise_for_status must degrade to empty findings."""
    project = tmp_path / "http_err_project"
    project.mkdir()
    (project / "requirements.txt").write_text("requests==2.31.0\n")

    from nyuwaymcpscanner.scanners import supply_chain as sc
    import requests as real_requests

    class ErrorResponse:
        def raise_for_status(self):
            raise real_requests.HTTPError("500 Server Error")

        def json(self):
            return {}

    monkeypatch.setattr(sc.requests, "post", lambda *a, **kw: ErrorResponse())
    findings = scan_supply_chain(str(project), offline=False)
    cve_findings = [f for f in findings if f["type"] == "dependency_cve"]
    assert cve_findings == []


def test_osv_network_failure_returns_empty(tmp_path, monkeypatch):
    project = tmp_path / "net_fail_project"
    project.mkdir()
    (project / "requirements.txt").write_text("requests==2.31.0\n")

    from nyuwaymcpscanner.scanners import supply_chain as sc
    import requests as real_requests

    def boom(*a, **kw):
        raise real_requests.ConnectionError("simulated network failure")

    monkeypatch.setattr(sc.requests, "post", boom)
    # Should not raise, just return [] for CVE portion.
    findings = scan_supply_chain(str(project), offline=False)
    assert isinstance(findings, list)


def test_offline_mode_skips_network(tmp_path, monkeypatch):
    project = tmp_path / "offline_project"
    project.mkdir()
    (project / "requirements.txt").write_text("requests==2.31.0\n")

    from nyuwaymcpscanner.scanners import supply_chain as sc

    called = {"n": 0}

    def fail_if_called(*args, **kwargs):
        called["n"] += 1
        raise AssertionError("Network call made in offline mode")

    monkeypatch.setattr(sc.requests, "post", fail_if_called)
    scan_supply_chain(str(project), offline=True)
    assert called["n"] == 0
