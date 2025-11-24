import sys
import re
import time
import hashlib
import asyncio
import aiohttp
import textwrap
from urllib.parse import urljoin, urlparse
from dataclasses import dataclass, field, asdict
from bs4 import BeautifulSoup
import jsbeautifier
from apify import Actor

# ==============================================================================
# [SECTION 1] CONFIGURATION & PATTERNS (Aapka Original Config)
# ==============================================================================

DEFAULT_CONFIG = {
    "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
    "signatures": {
        "CRITICAL": [
            {"name": "AWS Access Key", "regex": r'\b(AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}\b'},
            {"name": "AWS Secret Key", "regex": r'(?i)aws_secret_access_key\s*[:=]\s*["\']([A-Za-z0-9/+=]{40})["\']'},
            {"name": "Google API Key", "regex": r'\bAIza[0-9A-Za-z\\-_]{35}\b'},
            {"name": "Firebase Config", "regex": r'firebase(?:Config|app|App).*?apiKey.*?["\']([A-Za-z0-9_-]{20,})["\']'},
            {"name": "Slack Token", "regex": r'xox[baprs]-([0-9a-zA-Z]{10,48})'},
            {"name": "Stripe Key", "regex": r'(?:r|s)k_(?:live|test)_[0-9a-zA-Z]{24}'},
            {"name": "GitHub Token", "regex": r'(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}'},
            {"name": "Private Key", "regex": r'-----BEGIN ((?:RSA|DSA|EC|OPENSSH) PRIVATE KEY)-----'},
            {"name": "JWT Token", "regex": r'\beyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_.-]{20,}\b'},
        ],
        "HIGH": [
            {"name": "Internal IP", "regex": r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b'},
            {"name": "DB Connection", "regex": r'(?i)(mongodb|postgres|mysql|redis|amqp)://[^\s"\']+'},
            {"name": "S3 Bucket", "regex": r'[a-z0-9.-]+\.s3\.amazonaws\.com'},
            {"name": "Auth Header", "regex": r'(?i)Authorization\s*:\s*["\']?[\w\s]+["\']?'},
            {"name": "Generic Secret", "regex": r'(?i)(secret|password|passwd|token|apikey|api_key)[\s]*[:=][\s]*["\']([a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};:,.<>?\/\\|`~]{16,})["\']'},
        ],
        "MEDIUM": [
            {"name": "API Endpoint", "regex": r'["\']((?:/api/|/v[1-9]/|/rest/)[a-zA-Z0-9_/-]+)["\']'},
            {"name": "Hidden Parameter", "regex": r'[?&](admin|debug|test|token|auth|source)='},
            {"name": "Full HTTP URL", "regex": r'https?://[a-zA-Z0-9\-\._~:/?#\[\]@!$&\'()*+,;=%]+'},
        ],
        "VULN": [
            {"name": "XSS Sink", "regex": r'\.innerHTML\s*='},
            {"name": "Unsafe Eval", "regex": r'eval\s*\('},
            {"name": "Unsafe JSON", "regex": r'JSON\.parse\([^)]*\+[^)]*\)'},
            {"name": "LocalStorage", "regex": r'localStorage\.(getItem|setItem)\('},
        ],
        "INFO": [
            {"name": "Email", "regex": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'},
        ]
    }
}

# ==============================================================================
# [SECTION 2] DATA MODELS
# ==============================================================================

@dataclass
class Finding:
    type: str
    match: str
    source: str
    severity: str
    context: str
    hash: str = field(init=False)

    def __post_init__(self):
        raw = f"{self.type}:{self.match}:{self.source}"
        self.hash = hashlib.md5(raw.encode()).hexdigest()

@dataclass
class ScanStats:
    start_time: float = time.time()
    urls_crawled: int = 0
    js_files_found: int = 0
    bytes_scanned: int = 0
    errors: int = 0
    external_js: int = 0
    inline_scripts: int = 0

# ==============================================================================
# [SECTION 3] CORE ENGINE (Aapka Original Logic)
# ==============================================================================

class JSHunterEngine:
    def __init__(self, start_url, max_depth, include_cdn, threads=15, timeout=25):
        self.start_url = start_url
        self.max_depth = max_depth
        self.include_cdn = include_cdn
        self.threads = threads
        self.timeout = timeout
        
        self.session = None
        self.visited = set()
        self.js_files = set()
        self.findings = []
        self.stats = ScanStats()
        
        # Safe scope extraction
        try:
            self.scope_domain = urlparse(start_url).netloc.replace("www.", "")
        except:
            self.scope_domain = ""

        # Compile Regex
        self.patterns = {}
        for sev, items in DEFAULT_CONFIG['signatures'].items():
            self.patterns[sev] = []
            for item in items:
                try:
                    self.patterns[sev].append({
                        "type": item["name"],
                        "regex": re.compile(item["regex"])
                    })
                except: pass

    async def get_session(self):
        if not self.session:
            conn = aiohttp.TCPConnector(limit=self.threads, ssl=False)
            headers = {
                'User-Agent': DEFAULT_CONFIG['user_agent'],
                'Accept': '*/*'
            }
            self.session = aiohttp.ClientSession(connector=conn, headers=headers)
        return self.session

    def is_javascript_resource(self, url, response_headers=None):
        parsed = urlparse(url)
        path = parsed.path.lower()
        if re.search(r'\.(js|mjs|jsx|ts|tsx)(\?|$|#)', path): return True, "Ext"
        if "javascript" in path or "script" in path: return True, "Path"
        if response_headers:
            ctype = response_headers.get('Content-Type', '').lower()
            if any(t in ctype for t in ['javascript', 'ecmascript', 'json']): return True, "Header"
        return False, None

    def is_in_scope(self, url):
        parsed = urlparse(url)
        netloc = parsed.netloc
        
        # Scan CDN files if enabled
        if self.include_cdn:
            cdn_domains = ['unpkg', 'cdnjs', 'jsdelivr', 'googleapis', 'cloudfront', 's3']
            if any(cdn in netloc for cdn in cdn_domains): return True
        
        if url.endswith('.js'): return True
        return self.scope_domain in netloc

    def is_false_positive(self, finding):
        match = finding.match.lower()
        ftype = finding.type
        context = finding.context.lower()
        
        if "IP" in ftype:
            if re.search(r'(version|v|jquery|min\.js)', context): return True
            if match in ['1.1.1.1', '127.0.0.1', '0.0.0.0']: return True
        if "Email" in ftype:
            if any(x in match for x in ['example', 'test', 'domain', 'noreply']): return True
            if match.endswith(('.png', '.jpg', '.gif', '.css')): return True
        if "Key" in ftype and "EXAMPLE" in finding.match.upper(): return True
        return False

    def analyze_content(self, url, content):
        if content is None: return
        try:
            text = content if isinstance(content, str) else content.decode('utf-8', errors='replace')
            if len(text) < 20: return

            # Skip huge files to prevent memory crash
            if len(text) > 1000000: return 

            # Optional: Beautify
            try: text = jsbeautifier.beautify(text)
            except: pass

            # Regex Scan
            for severity, items in self.patterns.items():
                for item in items:
                    for match in item['regex'].finditer(text):
                        match_str = match.group(0)
                        start = max(0, match.start() - 75)
                        end = min(len(text), match.end() + 75)
                        context = text[start:end].strip().replace('\n', ' ')

                        f = Finding(item['type'], match_str, url, severity, context)

                        if not self.is_false_positive(f):
                            if not any(e.hash == f.hash for e in self.findings):
                                self.findings.append(f)
                                # IMPORTANT: Push to Apify Dataset immediately
                                asyncio.create_task(Actor.push_data(asdict(f)))
                                Actor.log.info(f"[{severity}] Found {item['type']} in {url}")
        except Exception as e:
            pass

    async def process_js(self, session, url):
        if url in self.js_files: return
        self.js_files.add(url)
        try:
            content = None
            async with session.get(url, timeout=20, ssl=False) as resp:
                if resp.status == 200:
                    content = await resp.read()
            if content and len(content) > 0:
                self.stats.js_files_found += 1
                self.stats.external_js += 1
                self.analyze_content(url, content)
        except: pass

    def extract_all_js_sources(self, html, base_url):
        soup = BeautifulSoup(html, 'html.parser')
        js_sources = []
        
        # External
        for script in soup.find_all('script', src=True):
            src = script.get('src')
            if src: js_sources.append(('external', urljoin(base_url, src), None))
        
        # Inline
        for i, script in enumerate(soup.find_all('script', src=False)):
            if script.string and len(script.string.strip()) > 10:
                v_url = f"inline://{urlparse(base_url).netloc}/script_{i}"
                js_sources.append(('inline', v_url, script.string))
                
        # Regex Hidden
        potential = re.findall(r'["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', str(html))
        for p in potential:
            full = urljoin(base_url, p)
            if self.is_in_scope(full):
                js_sources.append(('regex', full, None))
        return js_sources

    async def process_url(self, url, depth):
        if depth > self.max_depth or url in self.visited: return
        self.visited.add(url)
        Actor.log.info(f"Crawling: {url}")

        session = await self.get_session()
        try:
            async with session.get(url, timeout=self.timeout, ssl=False) as resp:
                if resp.status != 200: return
                content = await resp.read()
                if not content: return

                is_js, _ = self.is_javascript_resource(url, resp.headers)
                if is_js:
                    if url not in self.js_files:
                        self.js_files.add(url)
                        self.analyze_content(url, content)
                    return

                html = content.decode('utf-8', errors='ignore')
                self.stats.urls_crawled += 1
                sources = self.extract_all_js_sources(html, url)

                for s_type, s_url, s_code in sources:
                    if s_type in ['external', 'regex']:
                        if s_url not in self.js_files and self.is_in_scope(s_url):
                            asyncio.create_task(self.process_js(session, s_url))
                    else:
                        if s_url not in self.js_files:
                            self.js_files.add(s_url)
                            self.analyze_content(s_url, s_code)

                if depth < self.max_depth:
                    links = [urljoin(url, a.get('href')) for a in BeautifulSoup(html, 'html.parser').find_all('a', href=True)]
                    tasks = [self.process_url(l, depth+1) for l in links if self.is_in_scope(l) and l not in self.visited]
                    if tasks: await asyncio.gather(*tasks)
        except Exception as e:
            self.stats.errors += 1

    async def run(self):
        await self.process_url(self.start_url, 1)
        if self.session: await self.session.close()

# ==============================================================================
# MAIN ENTRY POINT
# ==============================================================================

async def main():
    async with Actor:
        # Input Handling
        actor_input = await Actor.get_input() or {}
        
        # Support for Request List (Apify Standard) or simple string
        start_urls = actor_input.get('startUrls', [])
        max_depth = actor_input.get('maxDepth', 2)
        include_cdn = actor_input.get('includeCdn', False)

        if not start_urls:
            Actor.log.error("No start URLs provided!")
            return

        # Handle multiple URLs
        tasks = []
        for req in start_urls:
            url = req.get('url')
            if url:
                engine = JSHunterEngine(url, max_depth, include_cdn)
                tasks.append(engine.run())
        
        await asyncio.gather(*tasks)

if __name__ == '__main__':
    asyncio.run(main())
