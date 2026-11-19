I chose the Website Technologies Scraper because I am passionate about cybersecurity and data analysis, and I think this task involves both.

On the security side, once you know which technologies a website uses, and especially which versions, you can check whether any of them have known vulnerabilities (CVEs). An outdated WordPress plugin or an old jQuery version, for example, can point to a site that may be exposed. So, beyond the main purpose stated in the task, finding websites that use competitors' products, the same scraper can also be used to assess a site's potential attack surface.

On the data side, the task is about collecting and processing data at scale: extracting signals from each website, filtering them, and matching them against a fingerprint database to correctly identify the technologies. The results can then be aggregated to answer business questions, such as how many Shopify stores use a competing analytics tool.

After some research, I found webappanalyzer, an open-source, database of technology fingerprints that continues the original Wappalyzer rule set. It contains fingerprints for 7,704 technologies, stored as JSON files. Each technology has a set of rules, regular expressions, that describe the traces it leaves on a website: script URLs, JavaScript global variables, cookies, HTTP headers, meta tags, DOM elements, the page URL, DNS records and more. My tool collects these signals from each website and compares them against the rules. When a rule matches, the technology is detected, and the matched rule together with the value found on the site serves as proof.

Download the fingerprint database into the project folder:

```
git clone https://github.com/enthec/webappanalyzer.git
```

Before writing the scraper, I wrote a script (`database_analyze.py`) to understand the structure of the database. It loads all 27 JSON files from `src/technologies/` into a single dictionary, which contains **7,704 technologies**.

Each technology is described by a JSON object. Here is the entry for WordPress:

```json
"WordPress": {
  "cats": [1, 11],
  "cpe": "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*",
  "description": "WordPress is a free and open-source content management system...",
  "icon": "WordPress.svg",
  "website": "https://wordpress.org",
  "oss": true,
  "saas": true,
  "pricing": ["low", "recurring", "freemium"],

  "headers":   { "X-Pingback": "/xmlrpc\\.php$", "link": "rel=\"https://api\\.w\\.org/\"" },
  "html":      [ "<link rel=[\"']stylesheet[\"'] [^>]+/wp-(?:content|includes)/" ],
  "meta":      { "generator": "^WordPress(?: ([\\d.]+))?\\;version:\\1" },
  "scriptSrc": [ "/wp-(?:content|includes)/", "wp-embed\\.min\\.js" ],
  "js":        { "wp.ajax": "", "wp_username": "" },
  "dom":       [ "link[rel=stylesheet][href*='/wp-content/']" ],

  "implies":   ["PHP", "MySQL"]
}
```
**'Implies' adds the technologies too if the main technology is detected. For example wordpress adds PHP and MySQL because WordPress can't run without them**

The fields fall into three groups:

| Type | Fields | Purpose |
|------|--------|---------|
| **Informative** | `description`, `icon`, `website`, `oss`, `saas`, `pricing` | describe the technology; not used for detection |
| **Classification** | `cats`, `cpe` | `cats` holds category IDs, translated to names via `categories.json` (e.g. `1` → CMS, `11` → Blogs). `cpe` is the standard identifier used to look up known vulnerabilities (CVEs). |
| **Detection rules** | `scriptSrc`, `js`, `dom`, `headers`, `cookies`, `meta`, `html`, `scripts`, `url`, `dns`, ... | mostly regular expressions that describe the traces a technology leaves on a website |
| **Relations** | `implies`, `requires`, `excludes` | e.g. if WordPress is found, PHP and MySQL are implied |


This analysis told me the format needed for my scraper to collect from each website: one for each type of detection rule.

After the analysis i dowloaded the parquet folder with all the domains i made read_paquet.py to read the first 5 and made a collect.py to collect data from the site. I collected the networks, scripts, meta, cookies, headers and all the html. I tried [disney](https://www.disneystore.com/) and got the json bellow that was saved in `signals/disneystore.com.json` 

```json
{
  "domain": "disneystore.com",
  "error": null,
  "url": "https://www.disneystore.com/",
  "status": 403,
  "headers": {
    "server": "AkamaiGHost",
    "link": "<https://cdn.evgnet.com>;rel=\"preconnect\",<https://cdn.cookielaw.org>;rel=\"preconnect\",<https://assets.adobedtm.com>;rel=\"preconnect\",<https://cdn.cquotient.com>;rel=\"preconnect\",<https://fast.fonts.net>;rel=\"preconnect\", ...",
    "x-disney-akamai-rule": "Set Path Cookie\nWaiting Room",
    ...
  },
  "cookies": { "wr_entry_path": "/", "AKA_A2": "A" },
  "meta": {},
  "scriptSrc": [],
  "scripts": [],
  "network": [
    "https://disneystore.com/",
    "https://www.disneystore.com/",
    "https://fonts.twdc.com/InspireTWDC/2024.1.0/woff/InspireTWDC-Black.woff2",
    ...
  ],
  "html": "<html><head><title>Access Denied</title></head><body><h1>Access Denied</h1> ..."
}
```
The request was **blocked**: the status is `403` and the HTML is an "Access Denied" page. The `server: AkamaiGHost` header and the `AKA_A2` cookie show that the site is protected by Akamai, which detected the automated browser. Because of this, there are no scripts or meta tags to analyze.However, the response still leaks information. 
After some research, I switched from Playwright to **Patchright**, a patched version of Playwright that hides the traces left by browser automation. I also:

- launched the **real Google Chrome** installed on my machine (`channel="chrome"`) instead of the bundled Chromium, in a **visible window** (`headless=False`);
- removed my hardcoded user agent (`Chrome/124`), which didn't match the real browser version and made the browser look inconsistent.

I tested the first 5 domains. Three of them worked perfectly. One, `jcmobilecigars.com`, is no longer active: its name no longer resolves in DNS, so there is no website to analyze. The last one, `yourfamilylines.com`, was blocked by my antivirus as a potentially dangerous site, which can happen when an old domain expires and is bought by someone else. This raised a safety concern: a scraper visits arbitrary, unknown websites with a real browser, so some of them may be malicious. At scale, I would run the browsers in isolated, disposable containers rather than on a personal machine.

To make the browser look more human and harder to detect, I added mouse movements and scrolling with random distances and random pauses between them. To extract more data, I also made the scraper accept cookie banners. Because of GDPR, many websites don't load their analytics and marketing trackers until the visitor accepts cookies, so accepting the banner reveals more technologies.