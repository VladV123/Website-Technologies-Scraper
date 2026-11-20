import asyncio
import json
import os
import random
from patchright.async_api import async_playwright
from read_parquet import load_domains
from database_analyzer import load_fingerprints


SIGNALS_DIR = "signals1" 
COOKIE_TEXTS = ["Accept all", "Accept All", "Allow all", "I agree", "Agree", "Accept", "Acceptă", "OK"]

COLLECTOR = """
(jsPaths) => {
  const get = (path) => {
    let obj = window;
    for (const part of path.split('.')) {
      if (obj === null || obj === undefined) return undefined;
      try { obj = obj[part]; } catch (e) { return undefined; }
    }
    return obj;
  };

  const js = {};
  for (const path of jsPaths) {
    const value = get(path);
    if (value !== undefined && value !== null) {
      js[path] = (typeof value === 'string' || typeof value === 'number') ? String(value) : true;
    }
  }

  const meta = {};
  document.querySelectorAll('meta[name], meta[property]').forEach(m => {
    const key = (m.getAttribute('name') || m.getAttribute('property')).toLowerCase();
    meta[key] = m.getAttribute('content') || '';
  });

  const scriptSrc = [...document.scripts].map(s => s.src).filter(Boolean);
  const scripts = [...document.scripts]
    .filter(s => !s.src)
    .map(s => s.textContent.slice(0, 5000));

  return { js, meta, scriptSrc, scripts };
}
"""
async def act_like_human(page):
    for _ in range(random.randint(2, 4)):
        x = random.randint(100, 1200)
        y = random.randint(100, 700)
        await page.mouse.move(x, y, steps=random.randint(10, 25))
        await page.wait_for_timeout(random.randint(200, 600))

    for _ in range(random.randint(4, 7)):
        await page.mouse.wheel(0, random.randint(300, 700))
        await page.wait_for_timeout(random.randint(400, 1200))

    if random.random() < 0.5:
        await page.mouse.wheel(0, -random.randint(200, 500))
        await page.wait_for_timeout(random.randint(300, 800))

async def accept_cookies(page):
    for text in COOKIE_TEXTS:
        button = page.get_by_role("button", name=text)
        try:
            if await button.count() > 0:
                await button.first.click(timeout=2000)
                return text
        except Exception:
            pass
    return None

def load_js_paths():
    paths = set()
    for rules in load_fingerprints().values():
        paths.update(rules.get("js", {}).keys())
    return sorted(paths)

async def collect(browser, domain, js_paths):
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

        scripts_before = {url for url, kind in network if kind == "script"}
        consent = await accept_cookies(page)
        consent_scripts = []
        if consent:
            await page.wait_for_timeout(random.randint(1500, 2500))
            scripts_after = {url for url, kind in network if kind == "script"}
            consent_scripts = sorted(scripts_after - scripts_before)

        await act_like_human(page)
        await page.wait_for_timeout(random.randint(1500, 3000))
        data = await page.evaluate(COLLECTOR, js_paths)
        script_urls = set(data["scriptSrc"]) | {url for url, kind in network if kind == "script"}
        signals.update({
            "url":       page.url,
            "status":    resp.status if resp else None,
            "consent":   consent,
            "consentScripts": consent_scripts,
            "headers":   resp.headers if resp else {},
            "cookies":   {c["name"]: c["value"] for c in await context.cookies()},
            "js":        data["js"],
            "meta":      data["meta"],
            "scriptSrc": sorted(script_urls),
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

def short_result(signals):
    if signals["error"]:
        return f"ERROR    {signals['error'][:70]}"
    if "bitdefender" in signals["html"].lower():
        return f"ANTIVIRUS status {signals['status']}"
    status = signals["status"]
    if status in (401, 403, 429):
        label = "BLOCKED"
    elif status and status >= 400:
        label = "SITE_ERR"
    else:
        label = "OK"
    return f"{label} status {status}, {len(signals['scriptSrc'])} scripts, {len(signals['network'])} requests"

async def start():
    domains = load_domains()
    js_paths = load_js_paths()
    print(f"{len(domains)} domains to collect\n")

    ok = blocked = site_errors = antivirus = errors = 0

    async with async_playwright() as p:
        browser = await p.chromium.launch(channel="chrome", headless=False)

        for i, domain in enumerate(domains, start=1):
            if os.path.exists(os.path.join(SIGNALS_DIR, f"{domain}.json")):
                print(f"[{i}/{len(domains)}] {domain} SKIPPED  (already collected)")
                continue

            signals = await collect(browser, domain, js_paths)
            save_signals(signals)

            result = short_result(signals)
            print(f"[{i}/{len(domains)}] {domain} {result}")

            if result.startswith("OK"):
                ok += 1
            elif result.startswith("BLOCKED"):
                blocked += 1
            elif result.startswith("SITE_ERR"):
                site_errors += 1
            elif result.startswith("ANTIVIRUS"):
                antivirus += 1
            else:
                errors += 1

            await asyncio.sleep(random.uniform(1, 3))

        await browser.close()

    print(f"\nOK: {ok}   BLOCKED: {blocked}   SITE ERROR: {site_errors}   ANTIVIRUS: {antivirus}   ERROR: {errors}")

if __name__ == "__main__":
    asyncio.run(start())