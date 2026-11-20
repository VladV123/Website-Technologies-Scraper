# Website Technologies Scraper

A tool that visits websites with a real browser, collects the traces left by the technologies they use, and matches them against an open-source fingerprint database. For every detected technology, it saves the evidence that led to the conclusion.

## Setup

```
git clone https://github.com/enthec/webappanalyzer.git
pip install patchright pandas pyarrow lxml cssselect
```

Google Chrome must be installed, since the collector uses the real browser.

## Usage

```
python colect.py     # visits every domain and saves its signals to signals/<domain>.json
python match.py      # matches the signals against the fingerprints and writes results.json
```

## Output

`results.json` contains every input domain, its status and the detected technologies, each with its categories and the evidence:
```json
"somalidisablesupport.com": {
    "status": "ok",
    "url": "https://somalidisablesupport.com/",
    "technologies": [
      {
        "name": "Apache HTTP Server",
        "categories": [
          "Web servers"
        ],
        "evidence": [
          "headers Server: Apache"
        ]
      },
      {
        "name": "Astra",
        "categories": [
          "WordPress themes"
        ],
        "evidence": [
          "scriptSrc: https://somalidisablesupport.com/wp-content/themes/astra/assets/js/minified/frontend.min.js?ver=3.9.1",
          "dom: link[href*='themes/astra'] [href=https://somalidisablesupport.com/wp-content/themes/astra/assets/css/minified/mai]"
        ]
      },
      {
        "name": "Elementor",
        "categories": [
          "Page builders",
          "WordPress plugins"
        ],
        "evidence": [
          "scriptSrc: https://somalidisablesupport.com/wp-content/plugins/elementor/assets/js/frontend-modules.min.js?ver=3.35.8",
          "meta generator: Elementor 3.35.8; features: additional_custom_breakpoints; settings: css_print_method-external, goog",
          "dom: link[href*='/wp-content/plugins/elementor/']"
        ]
      },
```

I chose the Website Technologies Scraper because I am passionate about cybersecurity and data analysis, and I think this task involves both.

On the security side, once you know which technologies a website uses, and especially which versions, you can check whether any of them have known vulnerabilities (CVEs). An outdated WordPress plugin or an old jQuery version, for example, can point to a site that may be exposed. So, beyond the main purpose stated in the task, finding websites that use competitors' products, the same scraper can also be used to assess a site's potential attack surface.

On the data side, the task is about collecting and processing data at scale: extracting signals from each website, filtering them, and matching them against a fingerprint database to correctly identify the technologies. The results can then be aggregated to answer business questions, such as how many Shopify stores use a competing analytics tool.

After some research, I found webappanalyzer, an open-source, database of technology fingerprints that continues the original Wappalyzer rule set. It contains fingerprints for 7,704 technologies, stored as JSON files. Each technology has a set of rules, regular expressions, that describe the traces it leaves on a website: script URLs, JavaScript global variables, cookies, HTTP headers, meta tags, DOM elements, the page URL, DNS records and more. My tool collects these signals from each website and compares them against the rules. When a rule matches, the technology is detected, and the matched rule together with the value found on the site serves as proof.

Before writing the scraper, I wrote a script (`database_analyzer.py`) to understand the structure of the database. It loads all 27 JSON files from `src/technologies/` into a single dictionary, which contains **7,704 technologies**.

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

After the analysis i dowloaded the parquet folder with all the domains I made read_parquet.py to read the first 5 and made a collect.py to collect data from the site. I collected the networks, scripts, meta, cookies, headers and all the html. I tried [disney](https://www.disneystore.com/) and got the json bellow that was saved in `signals/disneystore.com.json` 

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

The request was **blocked**: the status is `403` and the HTML is an "Access Denied" page. The `server: AkamaiGHost` header and the `AKA_A2` cookie show that the site is protected by Akamai, which detected the automated browser. Because of this, there are no scripts or meta tags to analyze. However, the response still leaks information. 
After some research, I switched from Playwright to **Patchright**, a patched version of Playwright that hides the traces left by browser automation. I also:

- launched the **real Google Chrome** installed on my machine (`channel="chrome"`) instead of the bundled Chromium, in a **visible window** (`headless=False`);
- removed my hardcoded user agent (`Chrome/124`), which didn't match the real browser version and made the browser look inconsistent.

I tested the first 5 domains. Three of them worked perfectly. One, `jcmobilecigars.com`, is no longer active: its name no longer resolves in DNS, so there is no website to analyze. The last one, `yourfamilylines.com`, was blocked by my antivirus as a potentially dangerous site, which can happen when an old domain expires and is bought by someone else. This raised a safety concern: a scraper visits arbitrary, unknown websites with a real browser, so some of them may be malicious. At scale, I would run the browsers in isolated, disposable containers rather than on a personal machine.

To make the browser look more human and harder to detect, I added mouse movements and scrolling with random distances and random pauses between them. To extract more data, I also made the scraper accept cookie banners. Because of GDPR, many websites don't load their analytics and marketing trackers until the visitor accepts cookies, so accepting the banner reveals more technologies.

After running the collector on the whole domain list, I got: **OK: 153, BLOCKED: 3, SITE ERROR: 10, ANTIVIRUS: 16, ERROR: 18**.

153 sites (77%) loaded correctly and can be analyzed. Only 3 were still blocked by anti-bot protection after switching to Patchright. 10 sites exist but are broken on the owner's side, for example an expired SSL certificate or a suspended hosting account. 16 were blocked by my antivirus because the domains are flagged as dangerous, which is common for old domains that expired and were taken over. The remaining 18 failed to load at all, mostly because the domain no longer exists or the site didn't respond in time.

To analyze the sites flagged by the antivirus safely, I would run the browser in an isolated, disposable container instead of on my own machine.

Next, I matched the collected signals against the fingerprint database to see how many technologies I could identify.

The first version only checked script URLs, headers, cookies, meta tags, the HTML and inline scripts. It found **289 different technologies**, on 166 of the 200 sites. Checking every network request as well, not only scripts, raised this to **307**: tracking pixels and ad networks such as TikTok Pixel or PubMatic never appear as `<script>` tags. Finally, I added the URLs from the `Link` header, which still reveal technologies when a site blocks the browser and no scripts load, plus a few smaller fixes. This brought the total to **308 of the 477** technologies.

Missing websites don't explain the gap: even if the remaining domains behaved like the analyzed ones, I would reach about 370. The rest of the difference comes from the signal types I didn't check yet: JavaScript global variables (`js`, 3,366 technologies) and DOM elements (`dom`, 1,644), the 2nd and 3rd most used rule types in the database. Many technologies can only be detected through them.

I didn't analyze the 16 domains blocked by my antivirus, since visiting them on my own machine would be a security risk. Adding these two rule types made a big difference. DOM rules only needed the HTML I had already saved, but JavaScript variables only exist while the page is open, so I had to collect all the sites again. With both, my tool found **362 technologies**, 54 more than before.

Applying the same estimate as before, if all 200 domains could have been analyzed, I would reach about 436 of the 477 technologies, around 91%. The remaining gap comes from domains that no longer work, signals I still don't collect (such as DNS records) and the other limits described below.

## Main issues and how I would tackle them

My scraper opens arbitrary websites in a real browser, and 16 of the domains were flagged as dangerous by my antivirus. I didn't want to visit them on my own machine, so I left them out. In production, I would run every browser in an isolated container on a cloud server and delete it after each visit, so a malicious site couldn't affect anything else.

 Some domains no longer exist, others have an expired SSL certificate or a suspended hosting account. These aren't bugs in my tool, but they show that the list should be checked before crawling, and that failed domains should be retried later: when I ran the collector a second time, one site that had worked before timed out.

Bot protection was another problem. Disney Store blocked my first attempts through Akamai, and only switching to Patchright with a real Chrome got me past it. After that, only 3 sites were still blocked. I didn't go further, for example with paid proxies or CAPTCHA solving, because I would rather respect `robots.txt` and the sites' terms of use.

 My scraper looks for buttons with a few fixed texts, in English and Romanian ("Accept all", "I agree", "Acceptă"…), so it misses banners in other languages, and it can't reach banners loaded inside an `iframe`, which many consent platforms use. Since many trackers only load after consent, this means some analytics tools are still missed. To improve it, I would detect the most common consent platforms (OneTrust, Cookiebot, Didomi…) and click their buttons by their known IDs, which don't depend on the language, and also search inside the page's frames.

The fingerprint database can also contain errors. I found one in Shopify's URL rule: it's missing a colon (`https?//` instead of `https?://`), so it can never match. I fixed it in my code, but the rules should be checked against real data and the fixes sent back to the project.

Finally, my tool only looks at each site's homepage, so technologies used only on other pages, like the checkout or the cart, are missed. And because the collector only checks the JavaScript variables the fingerprints ask for, a new rule means collecting the sites again.

## How would I scale this to millions of domains in 1-2 months?

I would put all the domains in a queue (Redis, Kafka) and run many identical workers, each in its own container, spread over several machines. Each worker takes the next domain from the queue, so no domain is processed twice and a crashed worker doesn't lose any work. Since results are saved under the domain name, processing a domain again simply overwrites it. To go faster, I would just add more workers.

I would also keep the two steps I already separated in this project: collecting the signals and matching them. The raw signals would go to cheap storage, and the matching would run later as a separate job. When I improved my matcher here, I could rerun it on all 200 sites in minutes without opening a single website again. 

I would also limit how often each server is visited, so the crawler doesn't overload anyone, retry the temporary errors later and keep an eye on how many sites end up blocked or failing.

## How would I discover new technologies in the future?

The most useful source is the network traffic I already collect. Across all sites, I would count the external domains that no rule recognizes. A domain that shows up on many sites, for example `cdn.something.com` on 40 of them, is almost certainly a technology missing from the database. After checking what it is, I would write a new rule for it.

The same idea works for the other signals: `<meta name="generator">` values, cookie names and JavaScript variables that no rule explains. 