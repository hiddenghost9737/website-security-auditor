import re
import asyncio
import hashlib
import aiohttp
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import jsbeautifier
from apify import Actor

# --- CONFIGURATION ---
SIGNATURES = {
    "CRITICAL": [
        {"name": "AWS Access Key", "regex": r'\b(AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}\b'},
        {"name": "Google API Key", "regex": r'\bAIza[0-9A-Za-z\\-_]{35}\b'},
        {"name": "Private Key", "regex": r'-----BEGIN ((?:RSA|DSA|EC|OPENSSH) PRIVATE KEY)-----'},
        {"name": "Slack Token", "regex": r'xox[baprs]-([0-9a-zA-Z]{10,48})'},
    ],
    "HIGH": [
        {"name": "DB Connection", "regex": r'(?i)(mongodb|postgres|mysql|redis|amqp)://[^\s"\']+'},
        {"name": "Auth Header", "regex": r'(?i)Authorization\s*:\s*["\']?[\w\s]+["\']?'},
    ],
    "MEDIUM": [
        {"name": "API Endpoint", "regex": r'["\']((?:/api/|/v[1-9]/|/rest/)[a-zA-Z0-9_/-]+)["\']'},
        {"name": "Hidden Parameter", "regex": r'[?&](admin|debug|test|token|auth|source)='},
    ]
}

class JSHunterActor:
    def __init__(self, start_urls, depth, include_cdn):
        self.start_urls = start_urls
        self.max_depth = depth
        self.include_cdn = include_cdn
        self.visited = set()
        self.js_scanned = set()
        self.session = None

        # Compile Regex
        self.patterns = {}
        for sev, items in SIGNATURES.items():
            self.patterns[sev] = []
            for item in items:
                self.patterns[sev].append({
                    "type": item["name"],
                    "regex": re.compile(item["regex"])
                })

    async def get_session(self):
        if not self.session:
            self.session = aiohttp.ClientSession()
        return self.session

    async def push_finding(self, finding_type, match, source_url, severity, context):
        # Create a unique hash to avoid duplicates
        unique_id = hashlib.md5(f"{finding_type}:{match}:{source_url}".encode()).hexdigest()
        
        await Actor.push_data({
            "finding_type": finding_type,
            "severity": severity,
            "match": match,
            "context": context,
            "source_url": source_url,
            "hash": unique_id
        })

    def analyze_content(self, url, content):
        if not content: return
        try:
            text = content.decode('utf-8', errors='replace')
            if len(text) > 500000: return # Skip massive files to save RAM

            # Optional: Beautify (warning: slows down processing)
            # text = jsbeautifier.beautify(text)

            for severity, items in self.patterns.items():
                for item in items:
                    for match in item['regex'].finditer(text):
                        match_str = match.group(0)
                        start = max(0, match.start() - 50)
                        end = min(len(text), match.end() + 50)
                        context = text[start:end].replace('\n', ' ').strip()
                        
                        # Async push to dataset
                        asyncio.create_task(self.push_finding(
                            item['type'], match_str, url, severity, context
                        ))
        except Exception as e:
            Actor.log.error(f"Error analyzing {url}: {e}")

    async def process_url(self, url, current_depth):
        if current_depth > self.max_depth or url in self.visited: return
        self.visited.add(url)
        Actor.log.info(f"Crawling: {url}")

        session = await self.get_session()
        try:
            async with session.get(url, timeout=15, ssl=False) as resp:
                if resp.status != 200: return
                content = await resp.read()
                
                # Check if it's JS file
                path = urlparse(url).path
                if path.endswith('.js') or 'javascript' in resp.headers.get('Content-Type', ''):
                    self.analyze_content(url, content)
                    return

                # If HTML, extract JS links
                html = content.decode('utf-8', errors='ignore')
                soup = BeautifulSoup(html, 'html.parser')
                
                # Extract scripts
                scripts = [urljoin(url, s.get('src')) for s in soup.find_all('script', src=True)]
                for s_url in scripts:
                    if s_url not in self.js_scanned:
                        if self.include_cdn or urlparse(s_url).netloc == urlparse(url).netloc:
                            self.js_scanned.add(s_url)
                            # Fetch and analyze JS
                            async with session.get(s_url, timeout=10, ssl=False) as js_resp:
                                if js_resp.status == 200:
                                    self.analyze_content(s_url, await js_resp.read())

                # Recursion for links
                if current_depth < self.max_depth:
                    links = [urljoin(url, a.get('href')) for a in soup.find_all('a', href=True)]
                    tasks = []
                    for link in links:
                        # Simple scope check: same domain only
                        if urlparse(link).netloc == urlparse(url).netloc:
                            tasks.append(self.process_url(link, current_depth + 1))
                    
                    if tasks: await asyncio.gather(*tasks)

        except Exception as e:
            Actor.log.warning(f"Failed to process {url}: {e}")

async def main():
    async with Actor:
        # Get input from Apify Dashboard
        actor_input = await Actor.get_input() or {}
        start_urls = actor_input.get('startUrls', [])
        depth = actor_input.get('maxDepth', 2)
        include_cdn = actor_input.get('includeCdn', False)

        if not start_urls:
            Actor.log.error("No Start URLs provided!")
            return

        engine = JSHunterActor(start_urls, depth, include_cdn)
        
        # Process request list
        tasks = []
        for req in start_urls:
            url = req.get('url')
            tasks.append(engine.process_url(url, 1))
        
        await asyncio.gather(*tasks)
        
        # Close session
        if engine.session:
            await engine.session.close()

if __name__ == '__main__':
    asyncio.run(main())
