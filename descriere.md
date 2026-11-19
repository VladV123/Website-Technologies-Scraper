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
