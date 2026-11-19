from read_parquet import load_domains
from database_analyzer import load_fingerprints, load_categories
from colect import SIGNALS_DIR, short_result
import json
import os
import re
from collections import Counter


RESULTS_JSON = "results.json"


def as_list(value):
    return value if isinstance(value, list) else [value]


def search(pattern, text):
    regex = pattern.split("\\;")[0]
    try:
        return re.search(regex, text, re.IGNORECASE)
    except re.error:
        return None                    


def match_site(signals, fingerprints):
    headers = {k.lower(): v for k, v in signals.get("headers", {}).items()}
    cookies = {k.lower(): v for k, v in signals.get("cookies", {}).items()}
    meta = signals.get("meta", {})
    html = signals.get("html", "")
    script_urls = signals.get("scriptSrc", [])
    network_urls = signals.get("network", [])
    inline_scripts = signals.get("scripts", [])

    found = {}

    for tech, rules in fingerprints.items():
        evidence = []
        for pattern in as_list(rules.get("scriptSrc", [])):
            for url in script_urls + network_urls:
                if search(pattern, url):
                    source = "scriptSrc" if url in script_urls else "network"
                    evidence.append(f"{source}: {url[:150]}")
                    break
        for pattern in as_list(rules.get("xhr", [])):
            for url in network_urls:
                if search(pattern, url):
                    evidence.append(f"xhr: {url[:150]}")
                    break
        for key, site_values in [("headers", headers), ("cookies", cookies), ("meta", meta)]:
            for name, pattern in rules.get(key, {}).items():
                value = site_values.get(name.lower())
                if value is None:
                    continue
                for p in as_list(pattern):
                    if search(p, value):
                        evidence.append(f"{key} {name}: {value[:100]}")
                        break
        for pattern in as_list(rules.get("html", [])):
            m = search(pattern, html)
            if m:
                evidence.append(f"html: ...{m.group(0)[:80]}...")
                break
        for pattern in as_list(rules.get("scripts", [])):
            for script in inline_scripts:
                m = search(pattern, script)
                if m:
                    evidence.append(f"scripts: ...{m.group(0)[:80]}...")
                    break

        if evidence:
            found[tech] = evidence

    return found


def apply_requires(found, fingerprints):
    changed = True
    while changed:
        changed = False
        for tech in list(found):
            required = [r.split("\\;")[0] for r in as_list(fingerprints[tech].get("requires", []))]
            if any(r not in found for r in required):
                del found[tech]
                changed = True
    return found


def apply_implies(found, fingerprints):
    queue = list(found)
    while queue:
        tech = queue.pop()
        for implied in as_list(fingerprints.get(tech, {}).get("implies", [])):
            implied = implied.split("\\;")[0]
            if implied in fingerprints and implied not in found:
                found[implied] = [f"implied by {tech}"]
                queue.append(implied)
    return found


def site_status(signals):
    if signals is None:
        return "not collected"
    return short_result(signals).split()[0].lower()


def load_signals(domain):
    path = os.path.join(SIGNALS_DIR, f"{domain}.json")
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def main():
    fingerprints = load_fingerprints()
    categories = load_categories()
    domains = load_domains()

    results = {}
    tech_counter = Counter()

    for i, domain in enumerate(domains, start=1):
        signals = load_signals(domain)
        status = site_status(signals)

        found = {}
        if signals and status not in ("error", "antivirus"):
            found = match_site(signals, fingerprints)
            found = apply_requires(found, fingerprints)   
            found = apply_implies(found, fingerprints)      

        technologies = []
        for tech in sorted(found):
            technologies.append({
                "name":       tech,
                "categories": [categories[str(c)]["name"] for c in fingerprints[tech].get("cats", []) if str(c) in categories],
                "evidence":   found[tech],
            })
            tech_counter[tech] += 1

        results[domain] = {
            "status":       status,
            "url":          signals.get("url") if signals else None,
            "technologies": technologies,
        }
        print(f"[{i}/{len(domains)}] {domain} {status} {len(technologies)} technologies")

    with open(RESULTS_JSON, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    analyzed = [r for r in results.values() if r["technologies"]]
    print(f"\nDistinct technologies found: {len(tech_counter)}")
    print(f"Domains with at least one technology: {len(analyzed)} / {len(domains)}")

    print("\nMost common technologies:")
    for tech, count in tech_counter.most_common(15):
        print(f"  {count:4}  {tech}")

    print(f"\nSaved {RESULTS_JSON}")


if __name__ == "__main__":
    main()