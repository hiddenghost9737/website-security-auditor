import sys
import re
import time
import hashlib
import asyncio
import aiohttp
import json
from datetime import datetime
from urllib.parse import urljoin, urlparse
from dataclasses import dataclass, field, asdict
from bs4 import BeautifulSoup
import jsbeautifier
from apify import Actor

# ==============================================================================
# [SECTION 1] CONFIGURATION & PATTERNS
# ==============================================================================

DEFAULT_CONFIG = {
    "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
    "signatures": {
        "CRITICAL": [
            {"name": "AWS Access Key", "regex": r'\b(AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}\b', "description": "AWS Access Key ID detected"},
            {"name": "AWS Secret Key", "regex": r'(?i)aws_secret_access_key\s*[:=]\s*["\']([A-Za-z0-9/+=]{40})["\']', "description": "AWS Secret Access Key found"},
            {"name": "Google API Key", "regex": r'\bAIza[0-9A-Za-z\\-_]{35}\b', "description": "Google API Key exposed"},
            {"name": "Firebase Config", "regex": r'firebase(?:Config|app|App).*?apiKey.*?["\']([A-Za-z0-9_-]{20,})["\']', "description": "Firebase API configuration found"},
            {"name": "Slack Token", "regex": r'xox[baprs]-([0-9a-zA-Z]{10,48})', "description": "Slack authentication token"},
            {"name": "Stripe Key", "regex": r'(?:r|s)k_(?:live|test)_[0-9a-zA-Z]{24}', "description": "Stripe API key detected"},
            {"name": "GitHub Token", "regex": r'(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}', "description": "GitHub personal access token"},
            {"name": "Private Key", "regex": r'-----BEGIN ((?:RSA|DSA|EC|OPENSSH) PRIVATE KEY)-----', "description": "Private cryptographic key found"},
            {"name": "JWT Token", "regex": r'\beyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_.-]{20,}\b', "description": "JSON Web Token (JWT) exposed"},
        ],
        "HIGH": [
            {"name": "Internal IP", "regex": r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b', "description": "Internal/Private IP address"},
            {"name": "DB Connection", "regex": r'(?i)(mongodb|postgres|mysql|redis|amqp)://[^\s"\']+', "description": "Database connection string"},
            {"name": "S3 Bucket", "regex": r'[a-z0-9.-]+\.s3\.amazonaws\.com', "description": "AWS S3 bucket URL"},
            {"name": "Auth Header", "regex": r'(?i)Authorization\s*:\s*["\']?[\w\s]+["\']?', "description": "Authorization header found"},
            {"name": "Generic Secret", "regex": r'(?i)(secret|password|passwd|token|apikey|api_key)[\s]*[:=][\s]*["\']([a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};:,.<>?\/\\|`~]{16,})["\']', "description": "Generic secret/password pattern"},
        ],
        "MEDIUM": [
            {"name": "API Endpoint", "regex": r'["\']((?:/api/|/v[1-9]/|/rest/)[a-zA-Z0-9_/-]+)["\']', "description": "API endpoint path"},
            {"name": "Hidden Parameter", "regex": r'[?&](admin|debug|test|token|auth|source)=', "description": "Sensitive URL parameter"},
            {"name": "Full HTTP URL", "regex": r'https?://[a-zA-Z0-9\-\._~:/?#\[\]@!$&\'()*+,;=%]+', "description": "Complete HTTP/HTTPS URL"},
        ],
        "VULN": [
            {"name": "XSS Sink", "regex": r'\.innerHTML\s*=', "description": "Potential XSS vulnerability (innerHTML)"},
            {"name": "Unsafe Eval", "regex": r'eval\s*\(', "description": "Dangerous eval() usage"},
            {"name": "Unsafe JSON", "regex": r'JSON\.parse\([^)]*\+[^)]*\)', "description": "Unsafe JSON parsing with concatenation"},
            {"name": "LocalStorage", "regex": r'localStorage\.(getItem|setItem)\(', "description": "localStorage usage detected"},
        ],
        "INFO": [
            {"name": "Email", "regex": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', "description": "Email address found"},
            {"name": "Phone Number", "regex": r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', "description": "Phone number pattern"},
        ]
    }
}

# ==============================================================================
# [SECTION 2] ENHANCED DATA MODELS
# ==============================================================================

@dataclass
class Finding:
    type: str
    match: str
    source: str
    severity: str
    context: str
    description: str = ""
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    hash: str = field(init=False)
    line_number: int = 0
    recommendation: str = ""

    def __post_init__(self):
        raw = f"{self.type}:{self.match}:{self.source}"
        self.hash = hashlib.md5(raw.encode()).hexdigest()
        
        # Add recommendations based on severity
        if self.severity == "CRITICAL":
            self.recommendation = "URGENT: Rotate this credential immediately and review access logs"
        elif self.severity == "HIGH":
            self.recommendation = "Review and restrict access to this sensitive information"
        elif self.severity == "MEDIUM":
            self.recommendation = "Verify if this information should be publicly accessible"
        elif self.severity == "VULN":
            self.recommendation = "Review code for potential security vulnerabilities"

@dataclass
class ScanStats:
    start_time: float = field(default_factory=time.time)
    end_time: float = 0
    urls_crawled: int = 0
    js_files_found: int = 0
    bytes_scanned: int = 0
    errors: int = 0
    external_js: int = 0
    inline_scripts: int = 0
    findings_by_severity: dict = field(default_factory=lambda: {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "VULN": 0, "INFO": 0})
    
    def to_dict(self):
        duration = self.end_time - self.start_time if self.end_time else time.time() - self.start_time
        return {
            "scan_duration_seconds": round(duration, 2),
            "urls_crawled": self.urls_crawled,
            "js_files_analyzed": self.js_files_found,
            "external_js_files": self.external_js,
            "inline_scripts": self.inline_scripts,
            "total_bytes_scanned": self.bytes_scanned,
            "errors_encountered": self.errors,
            "findings_by_severity": self.findings_by_severity,
            "total_findings": sum(self.findings_by_severity.values())
        }

# ==============================================================================
# [SECTION 3] CORE ENGINE WITH ENHANCED OUTPUT
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

        # Compile Regex with descriptions
        self.patterns = {}
        for sev, items in DEFAULT_CONFIG['signatures'].items():
            self.patterns[sev] = []
            for item in items:
                try:
                    self.patterns[sev].append({
                        "type": item["name"],
                        "regex": re.compile(item["regex"]),
                        "description": item.get("description", "")
                    })
                except: 
                    pass

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
        if re.search(r'\.(js|mjs|jsx|ts|tsx)(\?|$|#)', path): return True, "Extension"
        if "javascript" in path or "script" in path: return True, "Path"
        if response_headers:
            ctype = response_headers.get('Content-Type', '').lower()
            if any(t in ctype for t in ['javascript', 'ecmascript', 'json']): return True, "Content-Type"
        return False, None

    def is_in_scope(self, url):
        parsed = urlparse(url)
        netloc = parsed.netloc
        
        if self.include_cdn:
            cdn_domains = ['unpkg', 'cdnjs', 'jsdelivr', 'googleapis', 'cloudfront', 's3']
            if any(cdn in netloc for cdn in cdn_domains): 
                return True
        
        if url.endswith('.js'): 
            return True
        return self.scope_domain in netloc

    def is_false_positive(self, finding):
        match = finding.match.lower()
        ftype = finding.type
        context = finding.context.lower()
        
        if "IP" in ftype:
            if re.search(r'(version|v|jquery|min\.js)', context): return True
            if match in ['1.1.1.1', '127.0.0.1', '0.0.0.0', '255.255.255.255']: return True
        if "Email" in ftype:
            if any(x in match for x in ['example', 'test', 'domain', 'noreply', 'demo']): return True
            if match.endswith(('.png', '.jpg', '.gif', '.css', '.js')): return True
        if "Key" in ftype and "EXAMPLE" in finding.match.upper(): return True
        if "URL" in ftype and any(x in match for x in ['example.com', 'localhost']): return True
        return False

    def get_line_number(self, text, match_position):
        """Calculate line number for better reporting"""
        try:
            return text[:match_position].count('\n') + 1
        except:
            return 0

    def analyze_content(self, url, content):
        if content is None: 
            return
        try:
            text = content if isinstance(content, str) else content.decode('utf-8', errors='replace')
            if len(text) < 20: 
                return

            # Skip huge files
            if len(text) > 1000000: 
                Actor.log.warning(f"Skipping large file: {url} ({len(text)} bytes)")
                return 

            self.stats.bytes_scanned += len(text)

            # Beautify for better analysis
            try: 
                text = jsbeautifier.beautify(text)
            except: 
                pass

            # Regex Scan
            for severity, items in self.patterns.items():
                for item in items:
                    for match in item['regex'].finditer(text):
                        match_str = match.group(0)
                        match_pos = match.start()
                        
                        # Extract context
                        start = max(0, match_pos - 75)
                        end = min(len(text), match.end() + 75)
                        context = text[start:end].strip().replace('\n', ' ')
                        
                        # Calculate line number
                        line_num = self.get_line_number(text, match_pos)

                        # Create finding
                        f = Finding(
                            type=item['type'],
                            match=match_str,
                            source=url,
                            severity=severity,
                            context=context,
                            description=item.get('description', ''),
                            line_number=line_num
                        )

                        if not self.is_false_positive(f):
                            if not any(e.hash == f.hash for e in self.findings):
                                self.findings.append(f)
                                self.stats.findings_by_severity[severity] += 1
                                
                                # Push clean, readable data to Apify (without hash in main output)
                                finding_data = {
                                    "finding_id": f.hash[:8],  # Short ID for reference
                                    "severity": f.severity,
                                    "type": f.type,
                                    "description": f.description,
                                    "match": f.match,
                                    "source_file": f.source,
                                    "line_number": f.line_number,
                                    "context": f.context,
                                    "recommendation": f.recommendation,
                                    "timestamp": f.timestamp
                                }
                                asyncio.create_task(Actor.push_data(finding_data))
                                
                                Actor.log.info(f"[{severity}] {item['type']} found in {url} (Line {line_num})")
        except Exception as e:
            Actor.log.error(f"Error analyzing content from {url}: {str(e)}")
            self.stats.errors += 1

    async def process_js(self, session, url):
        if url in self.js_files: 
            return
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
        except Exception as e:
            Actor.log.debug(f"Failed to fetch {url}: {str(e)}")

    def extract_all_js_sources(self, html, base_url):
        soup = BeautifulSoup(html, 'html.parser')
        js_sources = []
        
        # External scripts
        for script in soup.find_all('script', src=True):
            src = script.get('src')
            if src: 
                js_sources.append(('external', urljoin(base_url, src), None))
        
        # Inline scripts
        for i, script in enumerate(soup.find_all('script', src=False)):
            if script.string and len(script.string.strip()) > 10:
                v_url = f"inline://{urlparse(base_url).netloc}/script_{i}"
                js_sources.append(('inline', v_url, script.string))
                self.stats.inline_scripts += 1
                
        # Regex-based JS discovery
        potential = re.findall(r'["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', str(html))
        for p in potential:
            full = urljoin(base_url, p)
            if self.is_in_scope(full):
                js_sources.append(('regex', full, None))
        
        return js_sources

    async def process_url(self, url, depth):
        if depth > self.max_depth or url in self.visited: 
            return
        self.visited.add(url)
        Actor.log.info(f"Crawling (depth {depth}): {url}")

        session = await self.get_session()
        try:
            async with session.get(url, timeout=self.timeout, ssl=False) as resp:
                if resp.status != 200: 
                    return
                content = await resp.read()
                if not content: 
                    return

                is_js, detection_method = self.is_javascript_resource(url, resp.headers)
                if is_js:
                    if url not in self.js_files:
                        self.js_files.add(url)
                        Actor.log.info(f"JS file detected via {detection_method}: {url}")
                        self.analyze_content(url, content)
                    return

                html = content.decode('utf-8', errors='ignore')
                self.stats.urls_crawled += 1
                sources = self.extract_all_js_sources(html, url)

                # Process all JS sources
                for s_type, s_url, s_code in sources:
                    if s_type in ['external', 'regex']:
                        if s_url not in self.js_files and self.is_in_scope(s_url):
                            asyncio.create_task(self.process_js(session, s_url))
                    else:  # inline
                        if s_url not in self.js_files:
                            self.js_files.add(s_url)
                            self.analyze_content(s_url, s_code)

                # Recursive crawling
                if depth < self.max_depth:
                    soup = BeautifulSoup(html, 'html.parser')
                    links = [urljoin(url, a.get('href')) for a in soup.find_all('a', href=True)]
                    tasks = [
                        self.process_url(link, depth + 1) 
                        for link in links 
                        if self.is_in_scope(link) and link not in self.visited
                    ]
                    if tasks: 
                        await asyncio.gather(*tasks, return_exceptions=True)
                        
        except Exception as e:
            Actor.log.error(f"Error processing {url}: {str(e)}")
            self.stats.errors += 1

    async def run(self):
        Actor.log.info(f"Starting scan on: {self.start_url}")
        Actor.log.info(f"Max depth: {self.max_depth}, Include CDN: {self.include_cdn}")
        
        await self.process_url(self.start_url, 1)
        
        if self.session: 
            await self.session.close()
        
        self.stats.end_time = time.time()
        
        # Generate final summary report
        summary = {
            "scan_info": {
                "target_url": self.start_url,
                "scan_date": datetime.utcnow().isoformat(),
                "max_depth": self.max_depth,
                "include_cdn": self.include_cdn
            },
            "statistics": self.stats.to_dict(),
            "findings_summary": {
                "total_findings": len(self.findings),
                "by_severity": self.stats.findings_by_severity,
                "unique_sources": len(set(f.source for f in self.findings))
            }
        }
        
        # Push summary as separate dataset entry
        await Actor.push_data({
            "type": "SCAN_SUMMARY",
            "summary": summary
        })
        
        Actor.log.info("="*60)
        Actor.log.info("SCAN COMPLETE")
        Actor.log.info(f"Total URLs Crawled: {self.stats.urls_crawled}")
        Actor.log.info(f"JS Files Analyzed: {self.stats.js_files_found}")
        Actor.log.info(f"Total Findings: {len(self.findings)}")
        Actor.log.info(f"Critical: {self.stats.findings_by_severity['CRITICAL']}")
        Actor.log.info(f"High: {self.stats.findings_by_severity['HIGH']}")
        Actor.log.info(f"Medium: {self.stats.findings_by_severity['MEDIUM']}")
        Actor.log.info(f"Vulnerabilities: {self.stats.findings_by_severity['VULN']}")
        Actor.log.info("="*60)

# ==============================================================================
# MAIN ENTRY POINT
# ==============================================================================

async def main():
    async with Actor:
        Actor.log.info("JS Hunter Advanced - Starting...")
        
        # Get input
        actor_input = await Actor.get_input() or {}
        
        start_urls = actor_input.get('startUrls', [])
        max_depth = actor_input.get('maxDepth', 2)
        include_cdn = actor_input.get('includeCdn', False)

        if not start_urls:
            Actor.log.error("❌ No start URLs provided!")
            Actor.log.info("Please provide 'startUrls' in the input")
            return

        Actor.log.info(f"Processing {len(start_urls)} target(s)")
        
        # Process all URLs
        tasks = []
        for req in start_urls:
            url = req.get('url')
            if url:
                Actor.log.info(f"Queuing scan for: {url}")
                engine = JSHunterEngine(url, max_depth, include_cdn)
                tasks.append(engine.run())
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
            Actor.log.info("✅ All scans completed successfully")
        else:
            Actor.log.warning("No valid URLs to process")

if __name__ == '__main__':
    asyncio.run(main())
