"""Tests for iocflow Layer 5 response/blocking (no network — sessions are faked)."""
import subprocess
import sys


from iocflow.block import (
    AbnormalBlocker,
    Blocker,
    BlockReport,
    BlockResult,
    BlockStatus,
    CrowdStrikeBlocker,
    PanEdlFeed,
    PanOsBlocker,
    ZscalerBlocker,
    block,
    default_blockers,
    guard,
    is_allowlisted,
    unblock,
)
from iocflow.enrich.models import EnrichmentRecord, EnrichmentReport, Verdict
from iocflow.models import Indicator


# ------------------------------ fakes -----------------------------

class FakeResp:
    def __init__(self, *, json_data=None, text="", ok=True, content=b"{}"):
        self._json = json_data if json_data is not None else {}
        self.text = text
        self._ok = ok
        self.content = content

    def raise_for_status(self):
        if not self._ok:
            raise RuntimeError("HTTP 500")

    def json(self):
        return self._json


class FakeSession:
    """Routes every call through a handler(method, url, kw) -> FakeResp."""

    def __init__(self, handler):
        self.handler = handler
        self.calls = []

    def post(self, url, **kw):
        self.calls.append(("POST", url, kw))
        return self.handler("POST", url, kw)

    def get(self, url, **kw):
        self.calls.append(("GET", url, kw))
        return self.handler("GET", url, kw)

    def request(self, method, url, **kw):
        self.calls.append((method, url, kw))
        return self.handler(method, url, kw)


class FakeBlocker:
    """A Blocker for runner tests."""

    def __init__(self, name="fake", kinds=("ip",), raise_exc=None):
        self.name = name
        self._kinds = set(kinds)
        self._raise = raise_exc
        self.calls = []

    def supports(self, kind):
        return kind in self._kinds

    def block(self, kind, value, *, action="prevent", dry_run=True):
        self.calls.append(("block", kind, value, action, dry_run))
        if self._raise:
            raise self._raise
        return BlockResult(self.name, kind, value, BlockStatus.BLOCKED, action=action)

    def unblock(self, kind, value, *, dry_run=True):
        self.calls.append(("unblock", kind, value, dry_run))
        return BlockResult(self.name, kind, value, BlockStatus.UNBLOCKED)


def _report(malicious=(), suspicious=(), benign=()):
    records = []
    for kind, value in malicious:
        records.append(EnrichmentRecord("vt", kind, value, verdict=Verdict.MALICIOUS, score=90))
    for kind, value in suspicious:
        records.append(EnrichmentRecord("vt", kind, value, verdict=Verdict.SUSPICIOUS, score=40))
    for kind, value in benign:
        records.append(EnrichmentRecord("vt", kind, value, verdict=Verdict.BENIGN))
    return EnrichmentReport(records=records)


# ----------------------------- guard ------------------------------

def test_guard_vetoes_benign_and_internal_ips():
    assert is_allowlisted("ip", "8.8.8.8")[0]
    assert is_allowlisted("ip", "10.0.0.5")[0]      # private
    assert is_allowlisted("ip", "127.0.0.1")[0]     # loopback
    assert not is_allowlisted("ip", "185.220.101.5")[0]


def test_guard_vetoes_benign_domains_urls_emails():
    assert is_allowlisted("domain", "google.com")[0]
    assert is_allowlisted("url", "https://google.com/path")[0]
    assert is_allowlisted("email", "alice@gmail.com")[0]
    assert not is_allowlisted("domain", "evil-domain.ru")[0]
    assert not is_allowlisted("url", "http://evil-domain.ru/x")[0]


def test_guard_never_allowlists_hashes():
    assert not is_allowlisted("sha256", "deadbeef")[0]
    assert not is_allowlisted("md5", "abc")[0]


def test_guard_partitions():
    inds = [Indicator("ip", "8.8.8.8"), Indicator("ip", "185.220.101.5")]
    allowed, vetoed = guard(inds)
    assert [i.value for i in allowed] == ["185.220.101.5"]
    assert vetoed[0][0].value == "8.8.8.8"


# --------------------------- PAN EDL feed -------------------------

def test_pan_edl_dry_run_writes_nothing(tmp_path):
    feed = PanEdlFeed(str(tmp_path))
    r = feed.block("ip", "1.2.3.4")  # dry_run default
    assert r.status is BlockStatus.DRY_RUN
    assert not (tmp_path / "ip.txt").exists()
    assert r.payload["entry"] == "1.2.3.4"


def test_pan_edl_block_unblock_and_dedup(tmp_path):
    feed = PanEdlFeed(str(tmp_path))
    assert feed.block("ip", "1.2.3.4", dry_run=False).status is BlockStatus.BLOCKED
    assert (tmp_path / "ip.txt").read_text().strip() == "1.2.3.4"
    # idempotent
    assert feed.block("ip", "1.2.3.4", dry_run=False).status is BlockStatus.ALREADY_BLOCKED
    # remove
    assert feed.unblock("ip", "1.2.3.4", dry_run=False).status is BlockStatus.UNBLOCKED
    assert (tmp_path / "ip.txt").read_text().strip() == ""


def test_pan_edl_url_strips_scheme(tmp_path):
    feed = PanEdlFeed(str(tmp_path))
    feed.block("url", "https://evil.com/path", dry_run=False)
    assert (tmp_path / "url.txt").read_text().strip() == "evil.com/path"


def test_pan_edl_unconfigured_skips():
    assert PanEdlFeed().block("ip", "1.2.3.4", dry_run=False).status is BlockStatus.SKIPPED


# ----------------------------- PAN-OS -----------------------------

def test_panos_only_supports_ip():
    b = PanOsBlocker("fw.example", "key")
    assert b.supports("ip") and not b.supports("domain")


def test_panos_dry_run_builds_uid_message():
    b = PanOsBlocker("fw.example", "key")
    r = b.block("ip", "1.2.3.4")
    assert r.status is BlockStatus.DRY_RUN
    assert "<register>" in r.payload["cmd"]
    assert '1.2.3.4' in r.payload["cmd"]


def test_panos_live_block_posts_uid(monkeypatch):
    sess = FakeSession(lambda m, u, kw: FakeResp(text='<response status="success"/>'))
    b = PanOsBlocker("fw.example", "key", session=sess)
    r = b.block("ip", "1.2.3.4", dry_run=False)
    assert r.status is BlockStatus.BLOCKED
    assert sess.calls[0][1].endswith("/api/")


def test_panos_unblock_uses_unregister():
    b = PanOsBlocker("fw.example", "key")
    r = b.unblock("ip", "1.2.3.4")
    assert "<unregister>" in r.payload["cmd"]


def test_panos_unconfigured_skips():
    assert PanOsBlocker().block("ip", "1.2.3.4", dry_run=False).status is BlockStatus.SKIPPED


# ----------------------------- Zscaler ----------------------------

def test_zscaler_supports_url_and_domain():
    z = ZscalerBlocker("https://zsapi/api/v1", "k", username="u", password="p")
    assert z.supports("url") and z.supports("domain") and not z.supports("ip")


def test_zscaler_dry_run_payload():
    z = ZscalerBlocker("https://zsapi/api/v1", "k", username="u", password="p")
    r = z.block("url", "https://evil.com/x")
    assert r.status is BlockStatus.DRY_RUN
    assert r.payload["body"]["blacklistUrls"] == ["evil.com/x"]
    assert "ADD_TO_LIST" in r.payload["endpoint"]


def test_zscaler_live_auth_post_activate():
    z = ZscalerBlocker("https://zsapi/api/v1", "abcdefghijklmnop", username="u", password="p",
                       session=FakeSession(lambda m, u, kw: FakeResp()))
    r = z.block("domain", "evil.com", dry_run=False)
    assert r.status is BlockStatus.BLOCKED
    urls = [c[1] for c in z._session.calls]
    assert any("authenticatedSession" in u for u in urls)
    assert any("blacklistUrls" in u for u in urls)
    assert any("activate" in u for u in urls)


def test_zscaler_unconfigured_skips():
    assert ZscalerBlocker().block("url", "http://x/y", dry_run=False).status is BlockStatus.SKIPPED


# --------------------------- CrowdStrike --------------------------

def test_crowdstrike_kind_mapping_and_dry_run():
    b = CrowdStrikeBlocker("id", "secret")
    assert b.supports("ip") and b.supports("sha256") and not b.supports("sha1")
    r = b.block("ip", "1.2.3.4")
    ind = r.payload["indicators"][0]
    assert ind["type"] == "ipv4" and ind["action"] == "prevent"


def test_crowdstrike_action_coerced():
    b = CrowdStrikeBlocker("id", "secret")
    r = b.block("domain", "evil.com", action="bogus")
    assert r.payload["indicators"][0]["action"] == "prevent"
    r2 = b.block("domain", "evil.com", action="detect")
    assert r2.payload["indicators"][0]["action"] == "detect"


def _falcon_handler(method, url, kw):
    if url.endswith("/oauth2/token"):
        return FakeResp(json_data={"access_token": "tok"})
    if method == "GET" and "queries/indicators" in url:
        return FakeResp(json_data={"resources": ["ioc-id-1"]})
    return FakeResp(json_data={"resources": ["x"], "errors": []}, content=b"{}")


def test_crowdstrike_live_block():
    b = CrowdStrikeBlocker("id", "secret", session=FakeSession(_falcon_handler))
    r = b.block("sha256", "abc123", dry_run=False)
    assert r.status is BlockStatus.BLOCKED


def test_crowdstrike_unblock_finds_then_deletes():
    sess = FakeSession(_falcon_handler)
    b = CrowdStrikeBlocker("id", "secret", session=sess)
    r = b.unblock("ip", "1.2.3.4", dry_run=False)
    assert r.status is BlockStatus.UNBLOCKED
    assert any(c[0] == "DELETE" for c in sess.calls)


# ---------------------------- Abnormal ----------------------------

def test_abnormal_experimental_skips_without_endpoint():
    b = AbnormalBlocker("token")
    r = b.block("email", "bad@evil.com", dry_run=False)
    assert r.status is BlockStatus.SKIPPED
    assert "experimental" in r.detail


def test_abnormal_dry_run_payload_and_no_unblock():
    b = AbnormalBlocker("token")
    r = b.block("email", "bad@evil.com")
    assert r.status is BlockStatus.DRY_RUN
    assert r.payload["senderAddress"] == "bad@evil.com"
    assert b.unblock("email", "bad@evil.com").status is BlockStatus.SKIPPED  # unblock unsupported


def test_abnormal_live_block_with_endpoint():
    b = AbnormalBlocker("token", block_path="/v1/block",
                        session=FakeSession(lambda m, u, kw: FakeResp()))
    r = b.block("domain", "evil.com", dry_run=False)
    assert r.status is BlockStatus.BLOCKED


# ----------------------------- runner -----------------------------

def test_block_selects_malicious_only_by_default():
    rep = _report(malicious=[("ip", "185.220.101.5")], suspicious=[("ip", "9.9.9.9")])
    fake = FakeBlocker(kinds=("ip",))
    out = block(rep, blockers=[fake])
    assert out.dry_run is True
    blocked_values = {c[2] for c in fake.calls}
    assert blocked_values == {"185.220.101.5"}  # suspicious excluded


def test_block_min_verdict_widens():
    rep = _report(malicious=[("ip", "185.220.101.5")], suspicious=[("ip", "45.9.9.9")])
    fake = FakeBlocker(kinds=("ip",))
    block(rep, blockers=[fake], min_verdict="suspicious")
    assert {c[2] for c in fake.calls} == {"185.220.101.5", "45.9.9.9"}


def test_block_guard_vetoes_benign_even_if_flagged():
    # A benign-allowlisted IP marked malicious must still be vetoed.
    rep = _report(malicious=[("ip", "8.8.8.8"), ("ip", "185.220.101.5")])
    fake = FakeBlocker(kinds=("ip",))
    out = block(rep, blockers=[fake])
    assert {c[2] for c in fake.calls} == {"185.220.101.5"}
    guarded = [r for r in out.results if r.target == "guard"]
    assert guarded and guarded[0].value == "8.8.8.8"


def test_block_dry_run_default_does_not_act(tmp_path):
    rep = _report(malicious=[("ip", "185.220.101.5")])
    feed = PanEdlFeed(str(tmp_path))
    out = block(rep, blockers=[feed])
    assert all(r.status is BlockStatus.DRY_RUN for r in out.results if r.target == "pan_edl")
    assert not (tmp_path / "ip.txt").exists()


def test_block_live_fans_out(tmp_path):
    rep = _report(malicious=[("ip", "185.220.101.5")])
    feed = PanEdlFeed(str(tmp_path))
    out = block(rep, blockers=[feed], dry_run=False)
    assert out.blocked and (tmp_path / "ip.txt").exists()


def test_block_explicit_indicators_bypass_verdict():
    fake = FakeBlocker(kinds=("ip", "domain"))
    block(indicators=[("ip", "185.220.101.5"), Indicator("domain", "evil.ru")], blockers=[fake])
    assert {c[2] for c in fake.calls} == {"185.220.101.5", "evil.ru"}


def test_block_kinds_filter():
    fake = FakeBlocker(kinds=("ip", "domain"))
    block(indicators=[("ip", "185.220.101.5"), ("domain", "evil.ru")], blockers=[fake],
          kinds={"ip"})
    assert {c[2] for c in fake.calls} == {"185.220.101.5"}


def test_block_resilient_to_raising_blocker():
    rep = _report(malicious=[("ip", "185.220.101.5")])
    out = block(rep, blockers=[FakeBlocker(raise_exc=RuntimeError("boom"))], dry_run=False)
    assert out.failed and "boom" in out.failed[0].error


def test_unblock_routes_to_unblock():
    fake = FakeBlocker(kinds=("ip",))
    out = unblock(indicators=[("ip", "185.220.101.5")], blockers=[fake])
    assert fake.calls[0][0] == "unblock"
    assert out.dry_run is True


def test_block_no_targets_is_empty_report():
    out = block(_report(malicious=[("ip", "185.220.101.5")]), blockers=[])
    assert out.results == [] or all(r.target == "guard" for r in out.results)


# --------------------------- default_blockers ---------------------

def test_default_blockers_from_env(tmp_path):
    env = {
        "IOCFLOW_PAN_EDL_PATH": str(tmp_path),
        "IOCFLOW_PANOS_HOST": "fw", "IOCFLOW_PANOS_API_KEY": "k",
        "IOCFLOW_FALCON_CLIENT_ID": "id", "IOCFLOW_FALCON_CLIENT_SECRET": "s",
        "IOCFLOW_ABNORMAL_API_TOKEN": "t",
    }
    names = {b.name for b in default_blockers(env)}
    assert names == {"pan_edl", "panos", "crowdstrike", "abnormal"}


def test_default_blockers_empty_without_env():
    assert default_blockers({}) == []


def test_default_blockers_zscaler_needs_all_four():
    partial = {"IOCFLOW_ZSCALER_BASE_URL": "u", "IOCFLOW_ZSCALER_API_KEY": "k"}
    assert default_blockers(partial) == []


# ------------------------- protocol + report ----------------------

def test_blockers_satisfy_protocol():
    for b in (PanEdlFeed("/tmp/x"), PanOsBlocker("h", "k"),
              ZscalerBlocker("u", "k", username="x", password="y"),
              CrowdStrikeBlocker("i", "s"), AbnormalBlocker("t")):
        assert isinstance(b, Blocker)


def test_report_summary_and_to_dict():
    rep = BlockReport(results=[
        BlockResult("pan_edl", "ip", "1.2.3.4", BlockStatus.BLOCKED),
        BlockResult("guard", "ip", "8.8.8.8", BlockStatus.SKIPPED, detail="allowlisted"),
    ], dry_run=False)
    assert rep.blocked and rep.skipped
    d = rep.to_dict()
    assert d["dry_run"] is False
    assert len(d["results"]) == 2
    assert "blocked" in rep.summary()


# ------------------------- import isolation -----------------------

def test_importing_block_does_not_load_ai():
    code = (
        "import sys; import iocflow.block; "
        "assert 'iocflow.ai' not in sys.modules, 'iocflow.ai eagerly imported'; "
        "print('ok')"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert "ok" in out.stdout
