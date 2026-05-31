"""Tests for the iocflow ingestion seam (no network — sources are stubbed/local)."""
import json

from iocflow.sources import (
    FileSource,
    GitHubAdvisorySource,
    MemorySeenStore,
    Poller,
    RssSource,
    SqliteSeenStore,
    Trigger,
    TriageResult,
    default_handler,
    default_sources,
)


# ------------------------------ stubs -----------------------------

class ListSource:
    """A Source that emits a fixed list of triggers (re-emits the same each poll)."""

    def __init__(self, triggers, name="stub"):
        self.name = name
        self._triggers = triggers
        self.polls = 0

    def poll(self):
        self.polls += 1
        return list(self._triggers)


def _trig(i, text="1.2.3.4 evil.test"):
    return Trigger(source="stub", id=str(i), text=text, title=f"item {i}")


# ------------------------------ Trigger ---------------------------

def test_trigger_key_and_to_dict():
    t = _trig(7)
    assert t.key == "stub:7"
    d = t.to_dict()
    assert d["key"] == "stub:7" and d["title"] == "item 7"


# ------------------------------ stores ----------------------------

def test_memory_seen_store():
    s = MemorySeenStore()
    assert not s.seen("a")
    s.mark("a")
    assert s.seen("a")


def test_sqlite_seen_store_persists_across_instances(tmp_path):
    db = str(tmp_path / "seen.sqlite")
    s1 = SqliteSeenStore(db)
    s1.mark("stub:1")
    assert s1.seen("stub:1") and s1.count() == 1
    s1.close()
    s2 = SqliteSeenStore(db)            # reopen — durable
    assert s2.seen("stub:1")
    s2.mark("stub:1")                   # idempotent
    assert s2.count() == 1


# ------------------------------ poller ----------------------------

def test_poller_handles_new_and_dedupes_seen():
    src = ListSource([_trig(1), _trig(2)])
    seen = []
    poller = Poller([src], handler=lambda t: seen.append(t.id) or t.id)
    first = poller.run_once()
    assert [r.trigger.id for r in first] == ["1", "2"]
    assert all(r.ok for r in first)
    second = poller.run_once()          # same triggers — all already seen
    assert second == []
    assert seen == ["1", "2"]           # handler ran once each


def test_poller_handler_error_is_a_result_not_a_crash_and_retries():
    src = ListSource([_trig(1)])
    calls = {"n": 0}

    def boom(_t):
        calls["n"] += 1
        raise ValueError("kaboom")

    poller = Poller([src], handler=boom)         # mark_on_error=False (default)
    r1 = poller.run_once()
    assert len(r1) == 1 and not r1[0].ok and "kaboom" in r1[0].error
    r2 = poller.run_once()                        # unmarked → retried
    assert len(r2) == 1
    assert calls["n"] == 2


def test_poller_mark_on_error_does_not_retry():
    src = ListSource([_trig(1)])
    calls = {"n": 0}

    def boom(_t):
        calls["n"] += 1
        raise RuntimeError("x")

    poller = Poller([src], handler=boom, mark_on_error=True)
    poller.run_once()
    poller.run_once()
    assert calls["n"] == 1                         # marked after first failure


def test_poller_one_bad_source_does_not_sink_the_rest():
    class Boom:
        name = "boom"

        def poll(self):
            raise ConnectionError("down")

    good = ListSource([_trig(9)])
    poller = Poller([Boom(), good], handler=lambda t: t.id)
    out = poller.run_once()
    assert [r.trigger.id for r in out] == ["9"]


def test_poller_run_forever_bounded_with_injected_sleep():
    src = ListSource([])  # nothing, just count iterations
    ticks = {"n": 0}
    poller = Poller([src], sleep_fn=lambda _s: ticks.__setitem__("n", ticks["n"] + 1))
    poller.run_forever(interval=60, max_iterations=3)
    assert src.polls == 3
    assert ticks["n"] == 2  # sleeps between iterations, not after the last


def test_poller_on_batch_callback_receives_results():
    src = ListSource([_trig(1)])
    batches = []
    poller = Poller([src], handler=lambda t: t.id)
    poller.run_forever(interval=1, max_iterations=1, on_batch=batches.append)
    assert len(batches) == 1 and batches[0][0].trigger.id == "1"


# --------------------------- default handler ----------------------

def test_default_handler_runs_lifecycle_and_never_raises():
    t = Trigger(source="x", id="1",
                text="APT28 used 185.220.101.5 and evil-domain.ru. Benign: 8.8.8.8.")
    res = default_handler(t)
    assert isinstance(res, TriageResult)
    assert "185.220.101.5" in res.entities.ips
    assert res.error is None
    # deterministic commentary/hunts present even with no API keys
    assert res.commentary is not None and res.hunts is not None
    json.dumps(res.to_dict())  # serializable


def test_default_handler_empty_text_is_safe():
    res = default_handler(Trigger(source="x", id="0", text=""))
    assert res.error is None and res.entities is not None


def test_default_handler_merges_structured_indicators():
    # A structured trigger (e.g. STIX) carries indicators directly; the handler
    # must fold them in even when the text alone wouldn't yield them.
    t = Trigger(source="taxii", id="1", text="[domain-name:value = 'evil.test']",
                indicators=[("domain", "evil.test"), ("sha256", "a" * 64),
                            ("cve", "CVE-2021-44228")])
    res = default_handler(t)
    assert "evil.test" in res.entities.domains
    assert "a" * 64 in res.entities.hashes["sha256"]
    assert "CVE-2021-44228" in res.entities.cves


# ------------------------------ RSS -------------------------------

RSS = """<?xml version="1.0"?>
<rss version="2.0"><channel><title>Vendor Advisories</title>
  <item>
    <title>Critical RCE in WidgetServer</title>
    <link>https://example.test/a/1</link>
    <guid>adv-1</guid>
    <description>Exploited from 185.220.101.5 via &lt;b&gt;CVE-2021-44228&lt;/b&gt;.</description>
    <pubDate>Sat, 31 May 2026 00:00:00 GMT</pubDate>
  </item>
</channel></rss>"""


def test_rss_source_parses_entries_offline():
    trigs = RssSource(RSS).poll()
    assert len(trigs) == 1
    t = trigs[0]
    assert t.id == "adv-1"
    assert "WidgetServer" in t.title
    assert "185.220.101.5" in t.text and "CVE-2021-44228" in t.text
    assert "<b>" not in t.text                       # HTML stripped
    assert t.source == "Vendor Advisories"           # feed title becomes the name


def test_rss_feeds_into_poller_and_extracts():
    poller = Poller([RssSource(RSS, name="vendor")])  # default lifecycle handler
    out = poller.run_once()
    assert len(out) == 1
    res = out[0].output
    assert "185.220.101.5" in res.entities.ips


# --------------------------- GitHub advisories --------------------

class FakeResp:
    def __init__(self, payload):
        self._p = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._p


class FakeGHSession:
    def __init__(self, payload):
        self.payload = payload
        self.last = None

    def get(self, url, params, headers, timeout):
        self.last = (url, params, headers)
        return FakeResp(self.payload)


def test_github_advisory_source_builds_triggers():
    payload = [
        {"ghsa_id": "GHSA-xxxx", "cve_id": "CVE-2026-0001", "severity": "critical",
         "summary": "RCE in libfoo", "description": "Heap overflow reachable via x.",
         "html_url": "https://github.com/advisories/GHSA-xxxx",
         "published_at": "2026-05-31T00:00:00Z",
         "vulnerabilities": [{"package": {"ecosystem": "pip"}}]},
        {"ghsa_id": "GHSA-yyyy", "severity": "low", "summary": "minor",
         "description": "", "vulnerabilities": []},
    ]
    sess = FakeGHSession(payload)
    src = GitHubAdvisorySource(severities=["critical"], token="t", session=sess)
    trigs = src.poll()
    assert [t.id for t in trigs] == ["GHSA-xxxx"]      # low filtered out
    t = trigs[0]
    assert ("cve", "CVE-2026-0001") in t.indicators
    assert "libfoo" in t.text and t.meta["severity"] == "critical"
    assert sess.last[2]["Authorization"] == "Bearer t"  # token used


def test_github_advisory_ecosystem_filter():
    payload = [
        {"ghsa_id": "G1", "severity": "critical", "summary": "a", "description": "",
         "vulnerabilities": [{"package": {"ecosystem": "npm"}}]},
        {"ghsa_id": "G2", "severity": "critical", "summary": "b", "description": "",
         "vulnerabilities": [{"package": {"ecosystem": "pip"}}]},
    ]
    src = GitHubAdvisorySource(severities=["critical"], ecosystems=["pip"],
                               session=FakeGHSession(payload))
    assert [t.id for t in src.poll()] == ["G2"]


# ------------------------------ FileSource ------------------------

def test_file_source_reads_dir_and_dedupes_by_mtime(tmp_path):
    f = tmp_path / "advisory.txt"
    f.write_text("Indicator 185.220.101.5 seen in the wild.")
    src = FileSource(str(tmp_path))
    store = MemorySeenStore()
    poller = Poller([src], store=store)
    out = poller.run_once()
    assert len(out) == 1 and "185.220.101.5" in out[0].output.entities.ips
    assert poller.run_once() == []                      # same mtime → seen


# ------------------------------ registry --------------------------

def test_default_sources_from_env():
    env = {"IOCFLOW_GITHUB_ADVISORIES": "true",
           "IOCFLOW_GITHUB_ADVISORY_SEVERITIES": "critical,high",
           "IOCFLOW_RSS_FEEDS": "https://a.test/feed,https://b.test/feed",
           "IOCFLOW_FILE_SOURCE_DIR": "/tmp/iocs"}
    srcs = default_sources(env)
    names = [s.name for s in srcs]
    assert "github-advisory" in names
    assert names.count("rss") == 2
    assert "file" in names


def test_default_sources_empty_env_is_empty():
    assert default_sources({}) == []


# ------------------------- import isolation -----------------------

def test_importing_core_does_not_load_sources_deps():
    import subprocess
    import sys
    code = (
        "import sys, iocflow; "
        "assert 'iocflow.sources' not in sys.modules; "
        "assert 'feedparser' not in sys.modules; "
        "print('ok')"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert out.returncode == 0 and "ok" in out.stdout, out.stderr


def test_importing_sources_does_not_eagerly_load_feedparser():
    # feedparser is only needed by RssSource.poll(); importing the package (or
    # constructing other sources) must not pull it in. (requests is already a
    # transitive of core via tldextract, so it's not a meaningful assertion here.)
    import subprocess
    import sys
    code = (
        "import sys, iocflow.sources; "
        "from iocflow.sources import GitHubAdvisorySource, FileSource, Poller; "
        "assert 'feedparser' not in sys.modules, 'feedparser eagerly imported'; "
        "print('ok')"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert out.returncode == 0 and "ok" in out.stdout, out.stderr
