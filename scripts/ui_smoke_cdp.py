"""Drive the live console over CDP: real clicks, real console errors.

Not a unit test — this is the browser doing what a human does, so a broken
handler or a JS exception shows up as a failure rather than a guess.
"""
import asyncio
import json
import os
import sys
import urllib.request

import websockets

URL = sys.argv[1] if len(sys.argv) > 1 else "http://3.106.151.93/"
# Configurable so a run can use a private browser instead of a shared :9222
DEV = f"http://127.0.0.1:{os.getenv('CDP_PORT', '9222')}"

errors, consoles = [], []


class CDP:
    def __init__(self, ws):
        self.ws, self.id, self.pending = ws, 0, {}

    async def reader(self):
        async for raw in self.ws:
            msg = json.loads(raw)
            if "id" in msg and msg["id"] in self.pending:
                self.pending.pop(msg["id"]).set_result(msg)
            elif msg.get("method") == "Runtime.exceptionThrown":
                d = msg["params"]["exceptionDetails"]
                errors.append(d.get("exception", {}).get("description") or d.get("text"))
            elif msg.get("method") == "Runtime.consoleAPICalled":
                if msg["params"]["type"] in ("error", "warning"):
                    consoles.append(" ".join(str(a.get("value")) for a in msg["params"]["args"]))
            elif msg.get("method") == "Page.javascriptDialogOpening":
                asyncio.create_task(self.call("Page.handleJavaScriptDialog", {"accept": True}))

    async def call(self, method, params=None, timeout=20):
        self.id += 1
        fut = asyncio.get_event_loop().create_future()
        self.pending[self.id] = fut
        await self.ws.send(json.dumps({"id": self.id, "method": method, "params": params or {}}))
        return await asyncio.wait_for(fut, timeout)

    async def js(self, expr):
        r = await self.call("Runtime.evaluate",
                            {"expression": expr, "returnByValue": True, "awaitPromise": True})
        return r.get("result", {}).get("result", {}).get("value")


async def main():
    targets = json.load(urllib.request.urlopen(f"{DEV}/json"))
    page = next(t for t in targets if t["type"] == "page")
    async with websockets.connect(page["webSocketDebuggerUrl"], max_size=2**24) as ws:
        c = CDP(ws)
        asyncio.create_task(c.reader())
        await c.call("Page.enable")
        await c.call("Runtime.enable")
        await c.call("Page.navigate", {"url": URL})
        await asyncio.sleep(4)

        async def state(label):
            v = await c.js("""(() => ({
                rows: document.querySelectorAll('#rows tr[data-id]').length,
                total: document.querySelector('#s-total').textContent,
                tech: document.querySelector('#s-tech').textContent,
                toast: document.querySelector('#toast').textContent,
                inj: getComputedStyle(document.querySelector('#inj-panel')).display,
                asrOff: document.querySelector('#asr-off').textContent,
                detail: (document.querySelector('#detail h3')||{}).textContent || '',
                hasBlockBtn: !!document.querySelector('#btn-block')
            }))()""")
            print(f"  {label:<26} rows={v['rows']:<3} total={v['total']:<4} tech={v['tech']:<3} "
                  f"toast={v['toast'][:44]!r}")
            return v

        print(f"\n=== {URL} ===")
        await state("initial")

        print("\n[1] Run attack simulation")
        await c.js("document.querySelector('#btn-attack').click()")
        await asyncio.sleep(5)
        await state("after attack sim")

        print("\n[1b] Attack simulation AGAIN (populated queue — dedupe regression)")
        await c.js("document.querySelector('#btn-attack').click()")
        await asyncio.sleep(6)
        await state("after second sim")

        print("\n[2] Injection test")
        await c.js("document.querySelector('#btn-inject').click()")
        await asyncio.sleep(6)
        v = await state("after injection")
        print(f"  injection panel display={v['inj']} asr_undefended={v['asrOff']}")

        print("\n[3] Select first alert row")
        await c.js("document.querySelector('#rows tr[data-id]').click()")
        await asyncio.sleep(2)
        v = await state("after row click")
        print(f"  detail title={v['detail'][:50]!r} block_button={v['hasBlockBtn']}")

        print("\n[4] Contain source IP")
        await c.js("document.querySelector('#btn-block').click()")
        await asyncio.sleep(3)
        await state("after contain")

        print("\n[5] Re-triage (defences on)")
        await c.js("document.querySelector('#btn-t-on').click()")
        await asyncio.sleep(3)
        await state("after re-triage")

        print("\n[6] Reset")
        await c.js("document.querySelector('#btn-reset').click()")
        await asyncio.sleep(3)
        await state("after reset")

        print(f"\nJS exceptions: {len(errors)}")
        for e in errors[:5]:
            print("   !", str(e)[:160])
        print(f"Console errors/warnings: {len(consoles)}")
        for e in consoles[:5]:
            print("   !", str(e)[:160])


asyncio.run(main())
