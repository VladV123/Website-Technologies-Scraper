import asyncio
import json
import os
import sys

from patchright.async_api import async_playwright

SIGNALS_DIR = "signals" 

JS_COLLECT = """
() => {
  const meta = {};
  document.querySelectorAll('meta[name], meta[property]').forEach(m => {
    const key = (m.getAttribute('name') || m.getAttribute('property')).toLowerCase();
    meta[key] = m.getAttribute('content') || '';
  });

  const scriptSrc = [...document.scripts].map(s => s.src).filter(Boolean);
  const scripts = [...document.scripts]
    .filter(s => !s.src)
    .map(s => s.textContent.slice(0, 5000));

  return { meta, scriptSrc, scripts };
}
"""

async def collect(browser, domain):
    context = await browser.new_context(no_viewport=True)
    page = await context.new_page()
    network = []
    page.on("request", lambda r: network.append((r.url, r.resource_type)))

    signals = {"domain": domain, "error": None}

    try:
        resp = await page.goto(f"https://{domain}", wait_until="domcontentloaded", timeout=20000)

        try:
            await page.wait_for_load_state("networkidle", timeout=8000)
        except Exception:
            pass                              

        await page.mouse.wheel(0, 2000)        
        await page.wait_for_timeout(4000)
        
        data = await page.evaluate(JS_COLLECT)
        signals.update({
            "url":       page.url,
            "status":    resp.status if resp else None,
            "headers":   resp.headers if resp else {},
            "cookies":   {c["name"]: c["value"] for c in await context.cookies()},
            "meta":      data["meta"],
            "scriptSrc": data["scriptSrc"],
            "scripts":   data["scripts"],
            "network":   [url for url, _ in network],
            "html":      await page.content(),
        })
    except Exception as e:
        signals["error"] = str(e)
    finally:
        await context.close()

    return signals

def save_signals(signals):
    os.makedirs(SIGNALS_DIR, exist_ok=True)
    path = os.path.join(SIGNALS_DIR, f"{signals['domain']}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(signals, f, indent=2, ensure_ascii=False)
    return path

def print_summary(signals):
    print(f"{signals['domain']}:")
    if signals["error"]:
        print(f"EROARE: {signals['error']}")
        return
    print(f"URL:     {signals['url']}  (status {signals['status']})")
    print(f"Headers: {len(signals['headers'])}")
    print(f"Cookies: {list(signals['cookies'])}")
    print(f"Meta:    {list(signals['meta'])}")
    print(f"Scripts: {len(signals['scriptSrc'])} externe, {len(signals['scripts'])} inline")
    print(f"Request: {len(signals['network'])}")
    print(f"HTML:    {len(signals['html'])} caractere")

async def start(domain):
    async with async_playwright() as p:
        browser = await p.chromium.launch(channel="chrome", headless=False)
        signals = await collect(browser, domain)
        await browser.close()

    print_summary(signals)
    path = save_signals(signals)
    print(f"{path}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(1)
    domain = sys.argv[1] 
    asyncio.run(start(domain))