import sys
import re
import time
import hashlib
import asyncio
import aiohttp
from datetime import datetime
from urllib.parse import urljoin, urlparse
from dataclasses import dataclass, field
from bs4 import BeautifulSoup
import jsbeautifier
from apify import Actor

# ==============================================================================
# ULTRA STRICT CONFIGURATION
# ==============================================================================

DEFAULT_CONFIG = {
    "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "signatures": {
        "CRITICAL": [
            {
                "name": "AWS Access Key",
                "regex": r'\b(AKIA[0-9A-Z]{16})\b',
                "description": "AWS Access Key ID detected",
                "validate": lambda m, ctx: (
                    len(m) == 20 and 
                    not any(x in ctx.lower() for x in ['example', 'sample', 'test', 'fake', 'dummy', 'placeholder']) and
                    not re.search(r'[A-Z]{20}', m)  # All caps = fake
                )
            },
            {
                "name": "Google API Key",
                "regex": r'\b(AIza[0-9A-Za-z_-]{35})\b',
                "description": "Google API Key exposed",
                "validate": lambda m, ctx: (
                    not any(x in ctx.lower() for x in ['example', 'sample', 'placeholder', 'gstatic', 'googleapis.com/widget']) and
                    len(set(m)) > 10  # Must have diversity
                )
            },
            {
                "name": "Slack Token",
                "regex": r'\b(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[0-9a-zA-Z]{24,})\b',
                "description": "Slack authentication token",
                "validate": lambda m, ctx: 'example' not in m.lower()
            },
            {
                "name": "Stripe Live Key",
                "regex": r'\b(sk_live_[0-9a-zA-Z]{24,})\b',
                "description": "Stripe LIVE API key (CRITICAL)",
                "validate": lambda m, ctx: '_live_' in m
            },
            {
                "name": "GitHub Token",
                "regex": r'\b(gh[ps]_[A-Za-z0-9_]{36,})\b',
                "description": "GitHub personal access token",
                "validate": lambda m, ctx: not any(x in ctx.lower() for x in ['example', 'your_token'])
            },
            {
                "name": "Private Key",
                "regex": r'-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
                "description": "Private cryptographic key",
                "validate": lambda m, ctx: '-----END' in ctx
            },
            {
                "name": "JWT Token",
                "regex": r'\b(eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_.-]{20,})\b',
                "description": "JSON Web Token exposed",
                "validate": lambda m, ctx: (
                    m.count('.') == 2 and 
                    len(m) > 60 and
                    'example' not in ctx.lower()
                )
            },
        ],
        "HIGH": [
            {
                "name": "Database Connection String",
                "regex": r'(?i)(mongodb|postgres|mysql)://[a-zA-Z0-9._%-]+:[^@\s]+@[a-zA-Z0-9.-]+',
                "description": "Database connection with credentials",
                "validate": lambda m, ctx: '@' in m and ':' in m and 'example' not in m.lower()
            },
            {
                "name": "Hardcoded Password",
                "regex": r'(?i)(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']{10,})["\']',
                "description": "Hardcoded password detected",
                "validate": lambda m, ctx: (
                    not any(x in m.lower() for x in ['password', '123456', 'your_password', 'enter', 'example']) and
                    len(m) >= 10
                )
            }
        ],
        "MEDIUM": [
            {
                "name": "API Endpoint",
                "regex": r'["\']((\/api\/v\d+|\/graphql)\/[a-zA-Z0-9_/-]{5,})["\']',
                "description": "Internal API endpoint",
                "validate": lambda m, ctx: len(m) > 10 and '/v' in m
            },
            {
                "name": "Admin Panel Path",
                "regex": r'["\'](\/(admin|dashboard|wp-admin)\/[a-zA-Z0-9_/-]+)["\']',
                "description": "Admin panel URL",
                "validate": lambda m, ctx: True
            }
        ],
        "VULN": [
            {
                "name": "DOM XSS Sink",
                "regex": r'\.innerHTML\s*=\s*[^;]*\+',
                "description": "Potential DOM XSS (innerHTML with concat)",
                "validate": lambda m, ctx: (
                    '+' in ctx and 
                    'innerHTML' in ctx and
                    not any(x in ctx.lower() for x in ['jquery', '.min.js', 'react', 'angular'])
                )
            },
            {
                "name": "Dangerous eval()",
                "regex": r'eval\s*\(\s*[^)]*[\+\[]',
                "description": "eval() with user input",
                "validate": lambda m, ctx: (
                    any(x in ctx for x in ['+', '[', 'concat']) and
                    not any(x in ctx.lower() for x in ['jquery', 'lodash', 'underscore'])
                )
            }
        ],
        "INFO": [
            {
                "name": "Email Address",
                "regex": r'\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b',
                "description": "Email address found",
                "validate": lambda m, ctx: (
                    not any(x in m.lower() for x in [
                        'example.com', 'test.com', 'domain.com', 'sample.com', 
                        '@example', 'noreply@', 'no-reply@', 'support@google', 
                        'admin@localhost', '.png', '.jpg', '.js'
                    ]) and
                    len(m.split('@')[0]) >= 3  # Username minimum 3 chars
                )
            }
        ]
    },
    
    # Ultra strict skip patterns
    "skip_patterns": [
        r'jquery.*\.js',
        r'bootstrap.*\.js',
        r'angular.*\.js',
        r'react.*\.js',
        r'vue.*\.js',
        r'lodash.*\.js',
        r'moment.*\.js',
        r'\.min\.js$',
        r'analytics\.js',
        r'gtag\.js',
        r'google.*analytics',
        r'gstatic\.com',  # Google static
        r'xjs\._',  # Google XJS
        r'googleapis\.com',
        r'cloudflare\.com',
        r'/og/_/',  # Google OG
    ],
    
    # Skip these domains completely
    "skip_domains": [
        'gstatic.com',
        'googleapis.com',
        'googletagmanager.com',
        'google-analytics.com',
        'cloudflare.com',
        'jsdelivr.net',
        'cdnjs.cloudflare.com',
        'unpkg.com'
    ]
}

# ==============================================================================
# DATA MODELS
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
    line_number: int = 0
    recommendation: str = ""
    confidence: str = "HIGH"

    def to_output(self):
        # Clean context - remove extra whitespace
        clean_context = ' '.join(self.context.split())
        
        return {
            "severity": self.severity,
            "type": self.type,
            "description": self.description,
            "finding": self.match[:150] + "..." if len(self.match) > 150 else self.match,
            "file": self.source.split('/')[-1] if '/' in self.source else self.source,
            "full_path": self.source,
            "line": self.line_number,
            "code_snippet": clean_context[:250] + "..." if len(clean_context) > 250 else clean_context,
            "recommendation": self.recommendation,
            "confidence": self.confidence,
            "found_at": self.timestamp
        }

@dataclass
class ScanStats:
    start_time: float = field(default_factory=time.time)
    end_time: float = 0
    urls_crawled: int = 0
    js_files_found: int = 0
    js_files_skipped: int = 0
    bytes_scanned: int = 0
    errors: int = 0
    findings_by_severity: dict = field(default_factory=lambda: {
        "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "VULN": 0, "INFO": 0
    })

# ==============================================================================
# ULTRA STRICT ENGINE
# ==============================================================================

class JSHunterEngine:
    def __init__(self, start_url, max_depth, include_cdn, min_confidence="HIGH", threads=10, timeout=20):
        self.start_url = start_url
        self.max_depth = max_depth
        self.include_cdn = include_cdn
        self.min_confidence = min_confidence
        self.threads = threads
        self.timeout = timeout
        
        self.session = None
        self.visited = set()
        self.js_files = set()
        self.findings = []
        self.finding_hashes = set()
        self.stats = ScanStats()
        
        try:
            self.scope_domain = urlparse(start_url).netloc.replace("www.", "")
        except:
            self.scope_domain = ""

        # Compile patterns
        self.patterns = {}
        for sev, items in DEFAULT_CONFIG['signatures'].items():
            self.patterns[sev] = []
            for item in items:
                try:
                    self.patterns[sev].append({
                        "type": item["name"],
                        "regex": re.compile(item["regex"], re.MULTILINE | re.IGNORECASE),
                        "description": item.get("description", ""),
                        "validate": item.get("validate", lambda m, ctx: True)
                    })
                except Exception as e:
                    Actor.log.debug(f"Pattern compile error: {e}")

        self.skip_patterns = [re.compile(p, re.IGNORECASE) for p in DEFAULT_CONFIG['skip_patterns']]
        self.skip_domains = DEFAULT_CONFIG['skip_domains']

    def should_skip_file(self, url):
        """Ultra strict file skipping"""
        parsed = urlparse(url)
        domain = parsed.netloc
        
        # Skip by domain
        if any(skip_dom in domain for skip_dom in self.skip_domains):
            return True
        
        # Skip by pattern
        for pattern in self.skip_patterns:
            if pattern.search(url):
                return True
        
        # Skip minified files
        if '.min.' in url or url.endswith('.min.js'):
            return True
            
        return False

    async def get_session(self):
        if not self.session:
            conn = aiohttp.TCPConnector(limit=self.threads, ssl=False)
            headers = {'User-Agent': DEFAULT_CONFIG['user_agent'], 'Accept': '*/*'}
            self.session = aiohttp.ClientSession(connector=conn, headers=headers)
        return self.session

    def is_in_scope(self, url):
        parsed = urlparse(url)
        netloc = parsed.netloc
        
        # Don't scan CDN unless explicitly enabled
        if not self.include_cdn:
            if any(cdn in netloc for cdn in self.skip_domains):
                return False
        
        return self.scope_domain in netloc

    def get_recommendation(self, severity, finding_type):
        recs = {
            "CRITICAL": {
                "default": "🚨 URGENT: Rotate credentials immediately. Review access logs.",
                "AWS Access Key": "Rotate via AWS IAM. Check CloudTrail for unauthorized access.",
                "Private Key": "Regenerate key pair. Review all systems using this key.",
                "JWT Token": "Invalidate token. Regenerate with shorter expiry.",
            },
            "HIGH": {
                "default": "⚠️ HIGH PRIORITY: Restrict access. Move to environment variables.",
                "Database Connection String": "Use environment variables and secret management.",
            },
            "VULN": {
                "default": "⚠️ VULNERABILITY: Fix this code pattern immediately.",
                "DOM XSS Sink": "Use textContent instead of innerHTML. Sanitize all inputs.",
                "Dangerous eval()": "Avoid eval(). Use JSON.parse() or safer alternatives.",
            }
        }
        return recs.get(severity, {}).get(finding_type, recs.get(severity, {}).get("default", "Review this finding"))

    def analyze_content(self, url, content):
        if content is None: 
            return
        
        try:
            text = content if isinstance(content, str) else content.decode('utf-8', errors='replace')
            if len(text) < 100: 
                return

            # Skip huge files
            if len(text) > 2000000:
                Actor.log.warning(f"Skipping large file: {url}")
                return

            self.stats.bytes_scanned += len(text)

            # Try beautify
            try:
                text = jsbeautifier.beautify(text)
            except:
                pass

            # Scan
            for severity, items in self.patterns.items():
                for item in items:
                    try:
                        for match in item['regex'].finditer(text):
                            match_str = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)
                            match_pos = match.start()
                            
                            # Extract clean context
                            start = max(0, match_pos - 100)
                            end = min(len(text), match.end() + 100)
                            context = text[start:end].strip()
                            
                            # Validate
                            if not item['validate'](match_str, context):
                                continue
                            
                            line_num = text[:match_pos].count('\n') + 1
                            
                            # Confidence
                            confidence = "HIGH" if len(match_str) >= 30 else "MEDIUM"
                            
                            # Skip low confidence
                            if self.min_confidence == "HIGH" and confidence != "HIGH":
                                continue

                            finding = Finding(
                                type=item['type'],
                                match=match_str,
                                source=url,
                                severity=severity,
                                context=context,
                                description=item['description'],
                                line_number=line_num,
                                recommendation=self.get_recommendation(severity, item['type']),
                                confidence=confidence
                            )

                            # Deduplicate
                            finding_hash = hashlib.md5(
                                f"{finding.type}:{finding.match}:{finding.source}".encode()
                            ).hexdigest()
                            
                            if finding_hash not in self.finding_hashes:
                                self.finding_hashes.add(finding_hash)
                                self.findings.append(finding)
                                self.stats.findings_by_severity[severity] += 1
                                
                                # Push clean output
                                asyncio.create_task(Actor.push_data(finding.to_output()))
                                
                                Actor.log.info(f"✓ [{severity}] {item['type']} in {url.split('/')[-1]}:{line_num}")
                    
                    except Exception as e:
                        Actor.log.debug(f"Pattern match error: {e}")
                        
        except Exception as e:
            Actor.log.error(f"Analysis error for {url}: {str(e)}")
            self.stats.errors += 1

    async def process_js(self, session, url):
        if url in self.js_files or self.should_skip_file(url):
            self.stats.js_files_skipped += 1
            return
            
        self.js_files.add(url)
        
        try:
            async with session.get(url, timeout=self.timeout, ssl=False) as resp:
                if resp.status == 200:
                    content = await resp.read()
                    if content and len(content) > 0:
                        self.stats.js_files_found += 1
                        self.analyze_content(url, content)
        except:
            pass

    def extract_js_sources(self, html, base_url):
        soup = BeautifulSoup(html, 'html.parser')
        js_sources = []
        
        # External only
        for script in soup.find_all('script', src=True):
            src = script.get('src')
            if src:
                full_url = urljoin(base_url, src)
                if not self.should_skip_file(full_url):
                    js_sources.append(('external', full_url, None))
        
        # Inline (substantial only)
        for i, script in enumerate(soup.find_all('script', src=False)):
            if script.string and len(script.string.strip()) > 200:
                v_url = f"inline://{urlparse(base_url).netloc}/script_{i}"
                js_sources.append(('inline', v_url, script.string))
        
        return js_sources

    async def process_url(self, url, depth):
        if depth > self.max_depth or url in self.visited: 
            return
        self.visited.add(url)
        
        session = await self.get_session()
        try:
            async with session.get(url, timeout=self.timeout, ssl=False) as resp:
                if resp.status != 200: 
                    return
                content = await resp.read()
                if not content: 
                    return

                html = content.decode('utf-8', errors='ignore')
                self.stats.urls_crawled += 1
                sources = self.extract_js_sources(html, url)

                for s_type, s_url, s_code in sources:
                    if s_type == 'external':
                        if s_url not in self.js_files and self.is_in_scope(s_url):
                            asyncio.create_task(self.process_js(session, s_url))
                    else:
                        if s_url not in self.js_files:
                            self.js_files.add(s_url)
                            self.analyze_content(s_url, s_code)

                # Crawl links
                if depth < self.max_depth:
                    soup = BeautifulSoup(html, 'html.parser')
                    links = [urljoin(url, a.get('href')) for a in soup.find_all('a', href=True)]
                    tasks = [
                        self.process_url(link, depth + 1) 
                        for link in links[:30]  # Limit
                        if self.is_in_scope(link) and link not in self.visited
                    ]
                    if tasks:
                        await asyncio.gather(*tasks, return_exceptions=True)
                        
        except Exception as e:
            self.stats.errors += 1

    async def run(self):
        Actor.log.info(f"🔍 Scanning: {self.start_url}")
        
        await self.process_url(self.start_url, 1)
        
        if self.session:
            await self.session.close()
        
        self.stats.end_time = time.time()
        
        # Summary
        summary = {
            "scan_info": {
                "target": self.start_url,
                "completed": datetime.utcnow().isoformat(),
                "config": {
                    "max_depth": self.max_depth,
                    "min_confidence": self.min_confidence
                }
            },
            "results": {
                "critical": self.stats.findings_by_severity["CRITICAL"],
                "high": self.stats.findings_by_severity["HIGH"],
                "medium": self.stats.findings_by_severity["MEDIUM"],
                "vulnerabilities": self.stats.findings_by_severity["VULN"],
                "info": self.stats.findings_by_severity["INFO"],
                "total_findings": sum(self.stats.findings_by_severity.values())
            },
            "statistics": {
                "urls_crawled": self.stats.urls_crawled,
                "js_files_analyzed": self.stats.js_files_found,
                "js_files_skipped": self.stats.js_files_skipped,
                "scan_duration": round(self.stats.end_time - self.stats.start_time, 2)
            }
        }
        
        await Actor.push_data({"type": "SCAN_SUMMARY", "summary": summary})
        
        Actor.log.info("="*50)
        Actor.log.info("✅ SCAN COMPLETE")
        Actor.log.info(f"   Critical: {self.stats.findings_by_severity['CRITICAL']}")
        Actor.log.info(f"   High: {self.stats.findings_by_severity['HIGH']}")
        Actor.log.info(f"   Total: {sum(self.stats.findings_by_severity.values())}")
        Actor.log.info("="*50)

# ==============================================================================
# MAIN
# ==============================================================================

async def main():
    async with Actor:
        actor_input = await Actor.get_input() or {}
        
        start_urls = actor_input.get('startUrls', [])
        max_depth = actor_input.get('maxDepth', 2)
        include_cdn = actor_input.get('includeCdn', False)
        min_confidence = actor_input.get('minConfidence', 'HIGH')

        if not start_urls:
            Actor.log.error("❌ No URLs provided")
            return

        for req in start_urls:
            url = req.get('url')
            if url:
                engine = JSHunterEngine(url, max_depth, include_cdn, min_confidence)
                await engine.run()

if __name__ == '__main__':
    asyncio.run(main())
