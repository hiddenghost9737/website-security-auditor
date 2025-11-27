import sys
import re
import time
import hashlib
import asyncio
import aiohttp
import json
from datetime import datetime
from urllib.parse import urljoin, urlparse
from dataclasses import dataclass, field
from bs4 import BeautifulSoup
import jsbeautifier
from apify import Actor

# ==============================================================================
# [SECTION 1] ENHANCED CONFIGURATION WITH BETTER PATTERNS
# ==============================================================================

DEFAULT_CONFIG = {
    "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
    "signatures": {
        "CRITICAL": [
            {
                "name": "AWS Access Key",
                "regex": r'\b(AKIA[0-9A-Z]{16})\b',
                "description": "AWS Access Key ID detected",
                "validate": lambda m, ctx: len(m) == 20 and not any(x in ctx.lower() for x in ['example', 'sample', 'test', 'fake', 'dummy'])
            },
            {
                "name": "AWS Secret Key",
                "regex": r'(?i)aws.{0,20}secret.{0,20}["\']([A-Za-z0-9/+=]{40})["\']',
                "description": "AWS Secret Access Key found",
                "validate": lambda m, ctx: len(m) == 40 and 'example' not in ctx.lower()
            },
            {
                "name": "Google API Key",
                "regex": r'\b(AIza[0-9A-Za-z_-]{35})\b',
                "description": "Google API Key exposed",
                "validate": lambda m, ctx: not any(x in ctx.lower() for x in ['example', 'sample', 'placeholder'])
            },
            {
                "name": "Slack Token",
                "regex": r'\b(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[0-9a-zA-Z]{24,})\b',
                "description": "Slack authentication token",
                "validate": lambda m, ctx: 'example' not in m.lower()
            },
            {
                "name": "Stripe API Key",
                "regex": r'\b((?:sk|pk)_live_[0-9a-zA-Z]{24,})\b',
                "description": "Stripe LIVE API key (HIGH RISK)",
                "validate": lambda m, ctx: '_live_' in m
            },
            {
                "name": "GitHub Token",
                "regex": r'\b(gh[ps]_[A-Za-z0-9_]{36,})\b',
                "description": "GitHub personal access token",
                "validate": lambda m, ctx: not any(x in ctx.lower() for x in ['example', 'your_token', 'fake'])
            },
            {
                "name": "Private Key",
                "regex": r'-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
                "description": "Private cryptographic key found",
                "validate": lambda m, ctx: '-----END' in ctx
            },
            {
                "name": "JWT Token",
                "regex": r'\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_.-]{10,})\b',
                "description": "JSON Web Token (JWT) exposed",
                "validate": lambda m, ctx: m.count('.') == 2 and len(m) > 50 and 'example' not in ctx.lower()
            },
            {
                "name": "Generic API Key",
                "regex": r'(?i)(?:api[_-]?key|apikey)\s*[:=]\s*["\']([a-zA-Z0-9_-]{32,})["\']',
                "description": "Generic API key found",
                "validate": lambda m, ctx: len(m) >= 32 and not any(x in m.lower() for x in ['example', 'your', 'xxx', 'test'])
            }
        ],
        "HIGH": [
            {
                "name": "Internal IP Address",
                "regex": r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b',
                "description": "Internal/Private IP address",
                "validate": lambda m, ctx: not any(x in ctx.lower() for x in ['version', 'v.', 'jquery', '.min.js', '.js?v=', 'build'])
            },
            {
                "name": "Database Connection String",
                "regex": r'(?i)(mongodb|postgres|mysql|redis)://[a-zA-Z0-9._%-]+:[a-zA-Z0-9._%-]+@[a-zA-Z0-9.-]+',
                "description": "Database connection string with credentials",
                "validate": lambda m, ctx: '@' in m and ':' in m and 'example' not in m.lower()
            },
            {
                "name": "S3 Bucket URL",
                "regex": r'https?://([a-z0-9.-]+)\.s3\.amazonaws\.com',
                "description": "AWS S3 bucket URL",
                "validate": lambda m, ctx: 'example' not in m
            },
            {
                "name": "Hardcoded Password",
                "regex": r'(?i)password\s*[:=]\s*["\']([^"\']{8,})["\']',
                "description": "Hardcoded password detected",
                "validate": lambda m, ctx: not any(x in m.lower() for x in ['example', 'password', '123456', 'your_password', 'enter'])
            }
        ],
        "MEDIUM": [
            {
                "name": "API Endpoint",
                "regex": r'["\']((\/api\/v\d+|\/rest\/v\d+|\/graphql)\/[a-zA-Z0-9_/-]+)["\']',
                "description": "API endpoint discovered",
                "validate": lambda m, ctx: len(m) > 10
            },
            {
                "name": "Admin Panel URL",
                "regex": r'["\'](\/(admin|dashboard|panel|wp-admin|administrator)\/[^"\']*)["\']',
                "description": "Admin/Dashboard URL found",
                "validate": lambda m, ctx: True
            },
            {
                "name": "Sensitive Parameter",
                "regex": r'[?&](api_key|token|access_token|auth|password|secret)=([^&\s"\']+)',
                "description": "Sensitive URL parameter",
                "validate": lambda m, ctx: not any(x in m.lower() for x in ['example', 'your', 'xxx'])
            }
        ],
        "VULN": [
            {
                "name": "DOM XSS Sink",
                "regex": r'(document\.write|\.innerHTML\s*=|\.outerHTML\s*=)\s*.*\+',
                "description": "Potential DOM-based XSS vulnerability",
                "validate": lambda m, ctx: '+' in ctx and 'innerHTML' in ctx
            },
            {
                "name": "Dangerous eval()",
                "regex": r'eval\s*\(\s*[^)]*\+',
                "description": "Dangerous eval() with concatenation",
                "validate": lambda m, ctx: '+' in ctx or 'concat' in ctx.lower()
            },
            {
                "name": "SQL Injection Pattern",
                "regex": r'(?i)query\s*=.*\+.*["\']SELECT|INSERT|UPDATE|DELETE',
                "description": "Potential SQL injection vulnerability",
                "validate": lambda m, ctx: True
            }
        ],
        "INFO": [
            {
                "name": "Email Address",
                "regex": r'\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b',
                "description": "Email address found",
                "validate": lambda m, ctx: not any(x in m.lower() for x in ['example.com', 'test.com', 'domain.com', 'sample.com', '@example', 'noreply@', 'no-reply@']) and not m.endswith(('.png', '.jpg', '.css', '.js'))
            },
            {
                "name": "Subdomain/Internal Domain",
                "regex": r'https?://([a-z0-9-]+)\.(internal|local|corp|dev|stage|staging)\.[a-z]+',
                "description": "Internal/Development domain",
                "validate": lambda m, ctx: True
            }
        ]
    },
    
    # Files/patterns to skip completely
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
        r'google.*analytics'
    ]
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
    description: str = ""
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    line_number: int = 0
    recommendation: str = ""
    confidence: str = "HIGH"  # HIGH, MEDIUM, LOW

    def to_output(self):
        """Clean output format"""
        return {
            "severity": self.severity,
            "type": self.type,
            "description": self.description,
            "match": self.match[:100] + "..." if len(self.match) > 100 else self.match,  # Truncate long matches
            "source_file": self.source,
            "line_number": self.line_number,
            "context": self.context[:200] + "..." if len(self.context) > 200 else self.context,
            "recommendation": self.recommendation,
            "confidence": self.confidence,
            "timestamp": self.timestamp
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
    findings_by_severity: dict = field(default_factory=lambda: {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "VULN": 0, "INFO": 0})
    
    def to_dict(self):
        duration = self.end_time - self.start_time if self.end_time else time.time() - self.start_time
        return {
            "scan_duration_seconds": round(duration, 2),
            "urls_crawled": self.urls_crawled,
            "js_files_analyzed": self.js_files_found,
            "js_files_skipped": self.js_files_skipped,
            "total_bytes_scanned": self.bytes_scanned,
            "errors_encountered": self.errors,
            "findings_by_severity": self.findings_by_severity,
            "total_findings": sum(self.findings_by_severity.values())
        }

# ==============================================================================
# [SECTION 3] SMART ENGINE WITH ADVANCED FILTERING
# ==============================================================================

class JSHunterEngine:
    def __init__(self, start_url, max_depth, include_cdn, filter_common_libs=True, min_confidence="MEDIUM", threads=15, timeout=25):
        self.start_url = start_url
        self.max_depth = max_depth
        self.include_cdn = include_cdn
        self.filter_common_libs = filter_common_libs
        self.min_confidence = min_confidence
        self.threads = threads
        self.timeout = timeout
        
        self.session = None
        self.visited = set()
        self.js_files = set()
        self.findings = []
        self.finding_hashes = set()  # For deduplication
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
                        "regex": re.compile(item["regex"], re.MULTILINE),
                        "description": item.get("description", ""),
                        "validate": item.get("validate", lambda m, ctx: True)
                    })
                except Exception as e:
                    Actor.log.warning(f"Failed to compile pattern {item.get('name')}: {e}")

        # Compile skip patterns
        self.skip_patterns = [re.compile(p, re.IGNORECASE) for p in DEFAULT_CONFIG['skip_patterns']]

    def should_skip_file(self, url):
        """Check if file should be skipped (common libraries)"""
        if not self.filter_common_libs:
            return False
        
        for pattern in self.skip_patterns:
            if pattern.search(url):
                Actor.log.debug(f"Skipping common library: {url}")
                return True
        return False

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
        if re.search(r'\.(js|mjs|jsx)(\?|$|#)', path): 
            return True
        if response_headers:
            ctype = response_headers.get('Content-Type', '').lower()
            if 'javascript' in ctype or 'ecmascript' in ctype:
                return True
        return False

    def is_in_scope(self, url):
        parsed = urlparse(url)
        netloc = parsed.netloc
        
        if self.include_cdn:
            cdn_domains = ['unpkg', 'cdnjs', 'jsdelivr', 'googleapis', 'cloudflare']
            if any(cdn in netloc for cdn in cdn_domains): 
                return True
        
        return self.scope_domain in netloc

    def calculate_confidence(self, finding, match_str, context):
        """Calculate confidence score"""
        confidence = "HIGH"
        
        # Lower confidence for very short matches
        if len(match_str) < 20:
            confidence = "MEDIUM"
        
        # Lower confidence if in minified code
        if re.search(r'[a-z]{1,2}\.[a-z]{1,2}\(', context) or 'var ' not in context:
            confidence = "MEDIUM"
        
        # Higher confidence for critical findings
        if finding.severity == "CRITICAL" and len(match_str) >= 30:
            confidence = "HIGH"
            
        return confidence

    def get_recommendation(self, severity, finding_type):
        """Get actionable recommendations"""
        recommendations = {
            "CRITICAL": {
                "default": "🚨 IMMEDIATE ACTION REQUIRED: Rotate/revoke this credential immediately. Review access logs for unauthorized usage.",
                "AWS Access Key": "Rotate AWS credentials immediately via IAM console. Check CloudTrail logs for unauthorized access.",
                "Private Key": "Regenerate key pair immediately. Review all systems using this key.",
                "JWT Token": "Invalidate this token and regenerate with shorter expiry. Check for token leakage.",
            },
            "HIGH": {
                "default": "⚠️ HIGH PRIORITY: Restrict access to this information. Review code for security improvements.",
                "Database Connection String": "Move credentials to environment variables. Use secret management system.",
                "Internal IP Address": "Avoid hardcoding internal IPs. Use service discovery or environment configs.",
            },
            "MEDIUM": {
                "default": "Review if this information should be publicly accessible.",
            },
            "VULN": {
                "default": "⚠️ SECURITY VULNERABILITY: Review and fix this code pattern to prevent exploits.",
                "DOM XSS Sink": "Use textContent instead of innerHTML. Sanitize all user inputs.",
                "Dangerous eval()": "Avoid eval(). Use safer alternatives like JSON.parse() or Function constructor.",
            }
        }
        
        return recommendations.get(severity, {}).get(finding_type, recommendations.get(severity, {}).get("default", ""))

    def analyze_content(self, url, content):
        if content is None: 
            return
        
        try:
            text = content if isinstance(content, str) else content.decode('utf-8', errors='replace')
            if len(text) < 50: 
                return

            # Skip huge files
            if len(text) > 2000000:
                Actor.log.warning(f"Skipping large file: {url} ({len(text)} bytes)")
                return

            self.stats.bytes_scanned += len(text)

            # Try to beautify
            original_text = text
            try:
                text = jsbeautifier.beautify(text)
            except:
                text = original_text

            # Scan with patterns
            for severity, items in self.patterns.items():
                for item in items:
                    try:
                        for match in item['regex'].finditer(text):
                            match_str = match.group(1) if match.lastindex else match.group(0)
                            match_pos = match.start()
                            
                            # Extract context
                            start = max(0, match_pos - 100)
                            end = min(len(text), match.end() + 100)
                            context = text[start:end].strip().replace('\n', ' ')
                            
                            # Validate with custom function
                            if not item['validate'](match_str, context):
                                continue
                            
                            # Calculate line number
                            line_num = text[:match_pos].count('\n') + 1
                            
                            # Calculate confidence
                            confidence = self.calculate_confidence(
                                type('F', (), {'severity': severity})(), 
                                match_str, 
                                context
                            )
                            
                            # Skip low confidence if filter enabled
                            if self.min_confidence == "HIGH" and confidence != "HIGH":
                                continue

                            # Create finding
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
                            finding_hash = hashlib.md5(f"{finding.type}:{finding.match}:{finding.source}".encode()).hexdigest()
                            if finding_hash not in self.finding_hashes:
                                self.finding_hashes.add(finding_hash)
                                self.findings.append(finding)
                                self.stats.findings_by_severity[severity] += 1
                                
                                # Push to Apify
                                asyncio.create_task(Actor.push_data(finding.to_output()))
                                
                                Actor.log.info(f"✓ [{severity}] {item['type']} in {url}:{line_num}")
                    
                    except Exception as e:
                        Actor.log.debug(f"Pattern error: {e}")
                        
        except Exception as e:
            Actor.log.error(f"Error analyzing {url}: {str(e)}")
            self.stats.errors += 1

    async def process_js(self, session, url):
        if url in self.js_files: 
            return
        
        if self.should_skip_file(url):
            self.stats.js_files_skipped += 1
            return
            
        self.js_files.add(url)
        
        try:
            async with session.get(url, timeout=20, ssl=False) as resp:
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
        
        # External scripts
        for script in soup.find_all('script', src=True):
            src = script.get('src')
            if src:
                full_url = urljoin(base_url, src)
                if not self.should_skip_file(full_url):
                    js_sources.append(('external', full_url, None))
        
        # Inline scripts (only if substantial)
        for i, script in enumerate(soup.find_all('script', src=False)):
            if script.string and len(script.string.strip()) > 100:  # Minimum 100 chars
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

                if self.is_javascript_resource(url, resp.headers):
                    if url not in self.js_files and not self.should_skip_file(url):
                        self.js_files.add(url)
                        self.analyze_content(url, content)
                    return

                html = content.decode('utf-8', errors='ignore')
                self.stats.urls_crawled += 1
                sources = self.extract_js_sources(html, url)

                # Process JS sources
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
                        for link in links[:50]  # Limit to 50 links per page
                        if self.is_in_scope(link) and link not in self.visited
                    ]
                    if tasks:
                        await asyncio.gather(*tasks, return_exceptions=True)
                        
        except Exception as e:
            self.stats.errors += 1

    async def run(self):
        Actor.log.info(f"🔍 Starting scan: {self.start_url}")
        
        await self.process_url(self.start_url, 1)
        
        if self.session:
            await self.session.close()
        
        self.stats.end_time = time.time()
        
        # Generate summary
        summary = {
            "scan_info": {
                "target_url": self.start_url,
                "scan_completed": datetime.utcnow().isoformat(),
                "configuration": {
                    "max_depth": self.max_depth,
                    "include_cdn": self.include_cdn,
                    "filter_libraries": self.filter_common_libs,
                    "min_confidence": self.min_confidence
                }
            },
            "statistics": self.stats.to_dict(),
            "summary": {
                "critical_findings": self.stats.findings_by_severity["CRITICAL"],
                "high_findings": self.stats.findings_by_severity["HIGH"],
                "total_findings": sum(self.stats.findings_by_severity.values()),
                "files_analyzed": self.stats.js_files_found,
                "files_skipped": self.stats.js_files_skipped
            }
        }
        
        await Actor.push_data({"type": "SCAN_SUMMARY", "data": summary})
        
        Actor.log.info("="*60)
        Actor.log.info("✅ SCAN COMPLETE")
        Actor.log.info(f"   Critical: {self.stats.findings_by_severity['CRITICAL']}")
        Actor.log.info(f"   High: {self.stats.findings_by_severity['HIGH']}")
        Actor.log.info(f"   Total Findings: {sum(self.stats.findings_by_severity.values())}")
        Actor.log.info("="*60)

# ==============================================================================
# MAIN ENTRY
# ==============================================================================

async def main():
    async with Actor:
        actor_input = await Actor.get_input() or {}
        
        start_urls = actor_input.get('startUrls', [])
        max_depth = actor_input.get('maxDepth', 2)
        include_cdn = actor_input.get('includeCdn', False)
        filter_libs = actor_input.get('filterCommonLibraries', True)
        min_confidence = actor_input.get('minConfidence', 'MEDIUM')  # HIGH, MEDIUM, LOW

        if not start_urls:
            Actor.log.error("❌ No URLs provided")
            return

        tasks = []
        for req in start_urls:
            url = req.get('url')
            if url:
                engine = JSHunterEngine(url, max_depth, include_cdn, filter_libs, min_confidence)
                tasks.append(engine.run())
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

if __name__ == '__main__':
    asyncio.run(main())
