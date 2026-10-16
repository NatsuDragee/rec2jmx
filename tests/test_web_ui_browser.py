"""End-to-end test of the web UI in headless Chrome/Edge via the DevTools protocol.

Skipped when no Chromium-based browser is found (set CHROME_PATH to override).
The browser runs with background networking disabled and a host-resolver rule that
makes every hostname except 127.0.0.1 unresolvable.
"""

import base64
import http.client
import json
import os
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time
from http.server import ThreadingHTTPServer
from urllib.parse import urlsplit

import pytest
from conftest import FIXTURE_SECRETS, fixture

from rec2jmx.web.server import make_handler

pytestmark = pytest.mark.browser

_CANDIDATES = [
    os.environ.get("CHROME_PATH", ""),
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    "/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
]


def _browser():
    for c in _CANDIDATES:
        if c and os.path.isfile(c):
            return c
    return shutil.which("chrome") or shutil.which("chromium")


class CDP:
    """Minimal Chrome DevTools Protocol client over a stdlib WebSocket."""

    def __init__(self, ws_url):
        u = urlsplit(ws_url)
        self.sock = socket.create_connection((u.hostname, u.port), timeout=30)
        key = base64.b64encode(os.urandom(16)).decode()
        self.sock.sendall((f"GET {u.path} HTTP/1.1\r\nHost: {u.hostname}:{u.port}\r\nUpgrade: websocket\r\n"
                           f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
        head = b""
        while b"\r\n\r\n" not in head:
            head += self.sock.recv(1)
        assert b" 101 " in head.split(b"\r\n")[0], head
        self.next_id = 0
        self.events = []

    def _send(self, text):
        data = text.encode()
        hdr = bytearray([0x81])
        n = len(data)
        if n < 126:
            hdr.append(0x80 | n)
        elif n < 65536:
            hdr += bytes([0x80 | 126]) + struct.pack(">H", n)
        else:
            hdr += bytes([0x80 | 127]) + struct.pack(">Q", n)
        mask = os.urandom(4)
        self.sock.sendall(bytes(hdr) + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))

    def _exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("DevTools connection closed")
            buf += chunk
        return buf

    def _recv(self):
        msg = b""
        while True:
            b1, b2 = self._exact(2)
            n = b2 & 0x7F
            if n == 126:
                n = struct.unpack(">H", self._exact(2))[0]
            elif n == 127:
                n = struct.unpack(">Q", self._exact(8))[0]
            payload = self._exact(n)
            if b1 & 0x0F == 8:
                raise ConnectionError("DevTools connection closed")
            msg += payload
            if b1 & 0x80:
                return json.loads(msg)

    def call(self, method, **params):
        self.next_id += 1
        self._send(json.dumps({"id": self.next_id, "method": method, "params": params}))
        while True:
            m = self._recv()
            if m.get("id") == self.next_id:
                if "error" in m:
                    raise RuntimeError(m["error"])
                return m.get("result", {})
            self.events.append(m)

    def js(self, expr):
        r = self.call("Runtime.evaluate", expression=expr, returnByValue=True, awaitPromise=True)
        if "exceptionDetails" in r:
            raise RuntimeError(r["exceptionDetails"])
        return r["result"].get("value")

    def wait_for(self, expr, timeout=30):
        end = time.time() + timeout
        while time.time() < end:
            if self.js(expr):
                return
            time.sleep(0.2)
        raise AssertionError(f"timed out waiting for: {expr}")


@pytest.fixture()
def ui():
    browser = _browser()
    if not browser:
        pytest.skip("No Chromium-based browser found (set CHROME_PATH); browser UI test not performed")
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(5 * 1024 * 1024))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    profile = tempfile.mkdtemp(prefix="rec2jmx-ui-")
    proc = subprocess.Popen([
        browser, "--headless=new", "--remote-debugging-port=0", f"--user-data-dir={profile}",
        "--no-first-run", "--no-default-browser-check", "--disable-background-networking",
        "--disable-component-update", "--disable-sync", "--disable-extensions", "--disable-default-apps",
        "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1", "about:blank",
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        port_file = os.path.join(profile, "DevToolsActivePort")
        end = time.time() + 30
        while not os.path.exists(port_file) or not open(port_file).read().strip():
            if time.time() > end:
                pytest.skip("Browser did not start its DevTools endpoint")
            time.sleep(0.2)
        devtools_port = int(open(port_file).read().split()[0])
        conn = http.client.HTTPConnection("127.0.0.1", devtools_port, timeout=30)
        conn.request("GET", "/json/list")
        pages = [t for t in json.loads(conn.getresponse().read()) if t["type"] == "page"]
        cdp = CDP(pages[0]["webSocketDebuggerUrl"])
        cdp.call("Runtime.enable")
        cdp.call("Page.enable")
        cdp.call("Page.navigate", url=f"http://127.0.0.1:{httpd.server_address[1]}/")
        cdp.wait_for("document.readyState === 'complete' && !!document.getElementById('file')")
        yield cdp
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        httpd.shutdown()
        httpd.server_close()
        shutil.rmtree(profile, ignore_errors=True)


def _upload(cdp, path):
    doc = cdp.call("DOM.getDocument")
    node = cdp.call("DOM.querySelector", nodeId=doc["root"]["nodeId"], selector="#file")
    cdp.call("DOM.setFileInputFiles", nodeId=node["nodeId"], files=[os.path.abspath(path)])


DRAG_JS = """(src, dst, pos) => {
  const dt = new DataTransfer();
  const r = dst.getBoundingClientRect();
  const y = pos === 'after' ? r.bottom - 2 : r.top + 2;
  src.dispatchEvent(new DragEvent('dragstart', {bubbles: true, dataTransfer: dt}));
  dst.dispatchEvent(new DragEvent('dragover', {bubbles: true, cancelable: true, dataTransfer: dt, clientY: y}));
  dst.dispatchEvent(new DragEvent('drop', {bubbles: true, cancelable: true, dataTransfer: dt, clientY: y}));
  src.dispatchEvent(new DragEvent('dragend', {bubbles: true, dataTransfer: dt}));
}"""


def drag(ui, src_selector, dst_selector, pos="before"):
    ui.js(f"({DRAG_JS})(document.querySelector({json.dumps(src_selector)}), "
          f"document.querySelector({json.dumps(dst_selector)}), {json.dumps(pos)})")


def tx_names(ui):
    return ui.js("[...document.querySelectorAll('#tree .tx')].map(n => n.textContent)")


def idle(ui):
    time.sleep(0.3)  # let the debounced refresh start
    ui.wait_for("document.getElementById('busy').hidden && !document.getElementById('openGenerate').disabled")


def req(rid):
    return f'.req[data-id="{rid}"]'


def visible(ui, element_id):
    return ui.js(f"(() => {{ const n = document.getElementById({json.dumps(element_id)}); "
                 "return !!n && getComputedStyle(n).display !== 'none' && n.getClientRects().length > 0; })()")


def test_screens_show_and_hide_for_real(ui):
    # Checks rendered visibility, not just the hidden attribute (a CSS display rule once overrode it).
    assert visible(ui, "importView") and not visible(ui, "workspace") and not visible(ui, "generateDialog")
    _upload(ui, fixture("har/shop_flows.har"))
    ui.wait_for("!document.getElementById('workspace').hidden")
    idle(ui)
    assert visible(ui, "workspace") and not visible(ui, "importView") and not visible(ui, "generateDialog")
    ui.js("document.getElementById('openGenerate').click()")
    assert visible(ui, "generateDialog") and visible(ui, "genForm") and not visible(ui, "genResult")
    ui.js("document.getElementById('closeGenerate').click()")
    assert not visible(ui, "generateDialog")
    ui.js("document.getElementById('newImport').click()")
    assert visible(ui, "importView") and not visible(ui, "workspace")


def test_workspace_review_drag_drop_and_generate(ui):
    assert "does not replay Android/iOS" in ui.js("document.querySelector('.notice').textContent")
    _upload(ui, fixture("har/shop_flows.har"))
    ui.wait_for("!document.getElementById('workspace').hidden && document.querySelectorAll('#tree .flow').length === 2")
    idle(ui)
    assert tx_names(ui) == ["TX_01_login", "TX_02_Checkout"]
    assert "HAR" in ui.js("document.getElementById('fileInfo').textContent")
    assert ui.js("document.getElementById('st-review').className") == "active"
    for secret in FIXTURE_SECRETS:
        assert secret not in ui.js("document.body.innerText")  # nothing revealed by default

    # Request detail: every recorded header, sensitive values masked until revealed.
    ui.js(f"document.querySelector({json.dumps(req('r0003'))}).click()")
    ui.wait_for("document.querySelector('#panel-request h2') && "
                "document.querySelector('#panel-request h2').textContent === 'TX_01_A02_api_v1_login'")
    rows = ui.js("[...document.querySelectorAll('#panel-request tbody tr')].map(r => [...r.cells].map(c => c.textContent))")
    by_name = {r[1]: r for r in rows}
    assert {"User-Agent", "Content-Type", "Cookie"} <= set(by_name)
    assert by_name["Cookie"][0] == "kept" and "chars)" in by_name["Cookie"][2]  # masked by default
    ui.js("document.querySelector('#panel-request .switch input').click()")
    ui.wait_for("[...document.querySelectorAll('#panel-request tbody td')].some(c => c.textContent === 'sid=old-session-cookie')")
    ui.js("[...document.querySelectorAll('#panel-request .subtab')].find(b => b.textContent === 'Body').click()")
    ui.wait_for("document.querySelector('#panel-request pre') && "
                "document.querySelector('#panel-request pre').textContent.includes('Sup3rS3cret!')")
    ui.js("document.querySelector('#panel-request .switch input').click()")  # hide again
    ui.wait_for("document.querySelector('#panel-request pre').textContent.includes('is hidden')")

    # Drag flow 2 above flow 1: transaction numbers follow.
    drag(ui, "#tree .flow:nth-child(2) .flow-head", "#tree .flow:nth-child(1) .flow-head", "before")
    idle(ui)
    ui.wait_for("document.querySelector('#tree .tx').textContent === 'TX_01_Checkout'")
    # Drag the feedback request into a new flow.
    drag(ui, req("r0007"), "#newFlowZone")
    idle(ui)
    ui.wait_for("document.querySelectorAll('#tree .flow').length === 3")
    assert tx_names(ui) == ["TX_01_Checkout", "TX_02_login", "TX_03_New_flow"]
    # Drag a request between flows: r0006 to just after r0004 (in the login flow).
    drag(ui, req("r0006"), req("r0004"), "after")
    idle(ui)
    ui.wait_for("[...document.querySelectorAll('#tree .flow:nth-child(2) .req')].map(r => r.dataset.id).join() === "
                "'r0001,r0003,r0004,r0006'")
    # Exclude a request with its checkbox.
    ui.js(f"document.querySelector({json.dumps(req('r0001') + ' input')}).click()")
    idle(ui)
    ui.wait_for(f"document.querySelector({json.dumps(req('r0001'))}).classList.contains('excluded')")
    # Accept the token correlation.
    ui.js("document.querySelector('.tab[data-tab=\"correlations\"]').click()")
    ui.wait_for("document.querySelectorAll('#panel-correlations tbody tr').length > 0")
    ui.js("[...document.querySelectorAll('#panel-correlations tbody tr')].find(r => r.cells[1].textContent === 'C02')"
          ".querySelector('input').click()")
    idle(ui)

    # Generate: summary, validation, XML preview, download.
    ui.js("document.getElementById('openGenerate').click()")
    ui.wait_for("!document.getElementById('generateDialog').hidden")
    assert ui.js("document.getElementById('secretPolicy').value") == "include"
    assert ui.js("document.getElementById('st-generate').className") == "active"
    ui.js("document.getElementById('generate').click()")
    ui.wait_for("!document.getElementById('genResult').hidden")
    result = ui.js("document.getElementById('genResult').innerText")
    # Checkout now runs before login, so the token correlation must be skipped with an explanation.
    assert "passed" in result and "C02 was not applied" in result and "were INCLUDED as recorded" in result
    assert "TX_01_Checkout" in result and "TX_03_New_flow" in result

    # Close, drag the login flow back to the top, and regenerate: C02 now applies.
    ui.js("document.getElementById('closeGenerate').click()")
    ui.wait_for("document.getElementById('generateDialog').hidden")
    drag(ui, "#tree .flow:nth-child(2) .flow-head", "#tree .flow:nth-child(1) .flow-head", "before")
    idle(ui)
    ui.wait_for("document.querySelector('#tree .tx').textContent === 'TX_01_login'")
    ui.js("document.getElementById('openGenerate').click()")
    ui.js("document.getElementById('generate').click()")
    ui.wait_for("!document.getElementById('genResult').hidden && "
                "document.getElementById('genResult').innerText.includes('Applied suggestions: C02')")
    assert ui.js("[...document.querySelectorAll('#genResult .card')].find(c => c.innerText.includes('Extractors'))"
                 ".querySelector('.v').textContent") == "1"
    assert ui.js("document.querySelector('#genResult a[download]').getAttribute('download')") == "shop_flows.jmx"
    ui.js("[...document.querySelectorAll('#genResult .subtab')].find(b => b.textContent === 'XML preview').click()")
    ui.wait_for("!!document.querySelector('#genResult pre.xml .x-tag')")
    xml = ui.js("document.querySelector('#genResult pre.xml').textContent")
    assert "<JSONPostProcessor" in xml and "Bearer ${C_token}" in xml
    assert 'testname="TX_01_A03_api_v1_orders_id"' in xml  # r0006 was moved into the login flow
    assert 'testname="TX_01_A01_api_v1_login"' in xml and "_root" not in xml  # r0001 is excluded
    exceptions = [e for e in ui.events if e.get("method") == "Runtime.exceptionThrown"]
    assert not exceptions, exceptions


def test_sanitized_banner_and_third_party_hosts(ui, tmp_path):
    entries = [{"request": {"method": "GET", "url": url, "headers": [{"name": "Accept", "value": "*/*"}]}}
               for url in ("https://app.example.test/api/a", "https://www.google-analytics.com/g/collect",
                           "https://bam.nr-data.net/events", "https://app.example.test/api/b")]
    har = tmp_path / "sanitized.har"
    har.write_text(json.dumps({"log": {"version": "1.2", "entries": entries}}), encoding="utf-8")
    _upload(ui, str(har))
    ui.wait_for("!document.getElementById('workspace').hidden")
    idle(ui)
    assert "Export HAR (with sensitive data)" in ui.js("document.getElementById('banners').innerText")
    chips = ui.js("[...document.querySelectorAll('#hostChips .chip')].map(c => c.innerText)")
    assert any("google-analytics" in c and "ANALYTICS" in c.upper() for c in chips)
    assert ui.js("document.getElementById('excludeThirdParty').textContent") == "Exclude third-party (2)"
    ui.js("document.getElementById('excludeThirdParty').click()")
    idle(ui)
    ui.wait_for("document.querySelectorAll('#hostChips .chip.off').length === 2")
    ui.wait_for("[...document.querySelectorAll('#tree .req:not(.excluded) .sname')].map(n => n.textContent).join() === "
                "'TX_01_A01_api_a,TX_01_A02_api_b'")
    ui.js("document.querySelector('#hostChips .chip.off').click()")  # reversible
    idle(ui)
    ui.wait_for("document.querySelectorAll('#hostChips .chip.off').length === 1")
    exceptions = [e for e in ui.events if e.get("method") == "Runtime.exceptionThrown"]
    assert not exceptions, exceptions


def test_malformed_upload_shows_error(ui):
    _upload(ui, fixture("har/malformed.har"))
    ui.wait_for("document.getElementById('import-error').textContent.length > 0")
    assert "malformed" in ui.js("document.getElementById('import-error').textContent")
    assert ui.js("document.getElementById('workspace').hidden") is True


def test_merge_flows_into_one_transaction(ui):
    _upload(ui, fixture("har/shop_flows.har"))
    ui.wait_for("!document.getElementById('workspace').hidden && document.querySelectorAll('#tree .flow').length === 2")
    idle(ui)
    assert ui.js("document.getElementById('mergeSelected').hidden") is True
    # Merge with next: two flows become one transaction, API numbers continue A01..A06.
    ui.js("document.querySelector('#tree .flow:nth-child(1) .merge-next').click()")
    idle(ui)
    ui.wait_for("document.querySelectorAll('#tree .flow').length === 1 && !!document.querySelector('#tree .flow-name input')")
    # Names are already updated while the name prompt is open; Enter keeps the suggested name.
    ui.wait_for("document.querySelectorAll('#tree .req .sname')[3].textContent === 'TX_01_A04_api_v1_orders'")
    ui.js("document.querySelector('#tree .flow-name input').dispatchEvent(new KeyboardEvent('keydown', {key: 'Enter', bubbles: true}))")
    idle(ui)
    assert tx_names(ui) == ["TX_01_login"]
    assert ui.js("[...document.querySelectorAll('#tree .req .sname')].map(n => n.textContent)") == [
        "TX_01_A01_root", "TX_01_A02_api_v1_login", "TX_01_A03_api_v1_users_id",
        "TX_01_A04_api_v1_orders", "TX_01_A05_api_v1_orders_id", "TX_01_A06_api_v1_feedback"]
    # Split two requests out into new flows, then merge non-adjacent flows via selection.
    drag(ui, req("r0006"), "#newFlowZone")
    idle(ui)
    drag(ui, req("r0007"), "#newFlowZone")
    idle(ui)
    ui.wait_for("document.querySelectorAll('#tree .flow').length === 3")
    ui.js("document.querySelector('#tree .flow:nth-child(1) .flow-select').click()")
    ui.js("document.querySelector('#tree .flow:nth-child(3) .flow-select').click()")
    assert ui.js("document.getElementById('mergeSelected').textContent") == "Merge selected (2)"
    ui.js("document.getElementById('mergeSelected').click()")
    idle(ui)
    ui.js("document.querySelector('#tree .flow-name input').dispatchEvent(new KeyboardEvent('keydown', {key: 'Enter', bubbles: true}))")
    idle(ui)
    ui.wait_for("document.querySelectorAll('#tree .flow').length === 2")
    assert tx_names(ui) == ["TX_01_login", "TX_02_New_flow"]
    assert ui.js("[...document.querySelectorAll('#tree .flow:nth-child(1) .req')].map(r => r.dataset.id).join()") == \
        "r0001,r0003,r0004,r0005,r0007"
    assert ui.js("document.getElementById('mergeSelected').hidden") is True  # selection cleared
    # The merged transaction is what gets generated.
    ui.js("document.getElementById('openGenerate').click()")
    ui.js("document.getElementById('generate').click()")
    ui.wait_for("!document.getElementById('genResult').hidden")
    result = ui.js("document.getElementById('genResult').innerText")
    assert "TX_01_login" in result and "TX_01_A05_api_v1_feedback" in result and "TX_02_A01_api_v1_orders_id" in result
    exceptions = [e for e in ui.events if e.get("method") == "Runtime.exceptionThrown"]
    assert not exceptions, exceptions


def _type_name(ui, text, key="Enter"):
    ui.js("(() => { const i = document.querySelector('#tree .flow-name input'); i.value = " + json.dumps(text) + ";"
          " i.dispatchEvent(new Event('input', {bubbles: true})); })()")
    preview = ui.js("document.querySelector('#tree .rename-preview').textContent")
    ui.js("document.querySelector('#tree .flow-name input').dispatchEvent(new KeyboardEvent('keydown', {key: "
          + json.dumps(key) + ", bubbles: true}))")
    return preview


def test_name_transactions(ui):
    _upload(ui, fixture("har/shop_flows.har"))
    ui.wait_for("!document.getElementById('workspace').hidden && document.querySelectorAll('#tree .flow').length === 2")
    idle(ui)
    # Rename button with a live preview of the final, sanitized name.
    ui.js("document.querySelector('#tree .flow:nth-child(2) .rename-btn').click()")
    ui.wait_for("!!document.querySelector('#tree .flow-name input')")
    assert _type_name(ui, "Checkout & Payment!") == "Will be named TX_02_Checkout_Payment"
    idle(ui)
    ui.wait_for("document.querySelectorAll('#tree .tx')[1].textContent === 'TX_02_Checkout_Payment'")
    # Escape cancels.
    ui.js("document.querySelector('#tree .flow:nth-child(1) .rename-btn').click()")
    _type_name(ui, "Should not stick", key="Escape")
    idle(ui)
    assert tx_names(ui) == ["TX_01_login", "TX_02_Checkout_Payment"]
    # Clicking the TX name also renames.
    ui.js("document.querySelector('#tree .flow:nth-child(1) .tx-btn').click()")
    _type_name(ui, "User Login")
    idle(ui)
    ui.wait_for("document.querySelector('#tree .tx').textContent === 'TX_01_User_Login'")
    # After a merge, the merged transaction is ready to be named.
    ui.js("document.querySelector('#tree .flow:nth-child(1) .merge-next').click()")
    idle(ui)
    ui.wait_for("document.querySelectorAll('#tree .flow').length === 1 && !!document.querySelector('#tree .flow-name input')")
    _type_name(ui, "Full purchase journey")
    idle(ui)
    ui.wait_for("document.querySelector('#tree .tx').textContent === 'TX_01_Full_purchase_journey'")
    assert ui.js("document.querySelector('#tree .req .sname').textContent") == "TX_01_A01_root"
    ui.js("document.getElementById('openGenerate').click()")
    ui.js("document.getElementById('generate').click()")
    ui.wait_for("!document.getElementById('genResult').hidden")
    ui.js("[...document.querySelectorAll('#genResult .subtab')].find(b => b.textContent === 'XML preview').click()")
    ui.wait_for("!!document.querySelector('#genResult pre.xml .x-tag')")
    xml = ui.js("document.querySelector('#genResult pre.xml').textContent")
    assert 'testname="TX_01_Full_purchase_journey"' in xml and 'testname="TX_01_A06_api_v1_feedback"' in xml
    exceptions = [e for e in ui.events if e.get("method") == "Runtime.exceptionThrown"]
    assert not exceptions, exceptions
