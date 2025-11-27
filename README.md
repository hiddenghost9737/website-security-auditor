```markdown
# 🔍 JS Hunter - Advanced JavaScript Security Scanner

**Automatically discovers and scans ALL JavaScript files on a website for security issues.**

## 🎯 What It Does

This actor automatically:
- ✅ Crawls your target website(s)
- ✅ Finds ALL JavaScript files (external, inline, hidden)
- ✅ Scans for exposed secrets, API keys, and credentials
- ✅ Detects security vulnerabilities (XSS, eval, etc.)
- ✅ Provides actionable recommendations

## 🚀 Features

### Automatic Discovery
- External JavaScript files (`<script src="...">`)
- Inline JavaScript (`<script>...</script>`)
- Hidden JS files found in HTML source
- Dynamic imports and lazy-loaded scripts
- Optional CDN scanning

### What It Finds

**CRITICAL Issues:**
- AWS Access Keys & Secret Keys
- Google API Keys
- Firebase Configurations
- Slack Tokens
- Stripe API Keys (Live & Test)
- GitHub Personal Access Tokens
- Private Keys (RSA, DSA, EC)
- JWT Tokens
- Generic API Keys

**HIGH Priority:**
- Internal IP Addresses
- Database Connection Strings
- S3 Bucket URLs
- Hardcoded Passwords

**MEDIUM Priority:**
- API Endpoints
- Admin Panel URLs
- Sensitive URL Parameters

**VULNERABILITIES:**
- DOM XSS Sinks
- Dangerous eval() usage
- SQL Injection patterns

**INFO:**
- Email Addresses
- Internal/Development Domains

## 📊 Input Configuration

```json
{
  "startUrls": [
    {"url": "https://yourwebsite.com"}
  ],
  "maxDepth": 2,
  "includeCdn": false,
  "filterCommonLibraries": true,
  "minConfidence": "MEDIUM"
}
```

### Parameters Explained

- **startUrls**: Target website(s) to scan
- **maxDepth**: How deep to crawl (1-5)
  - 1 = Only scan the start URL
  - 2 = Scan start URL + all linked pages (recommended)
  - 3+ = Deep crawl (slower)
- **includeCdn**: Scan CDN-hosted libraries (usually not needed)
- **filterCommonLibraries**: Skip jQuery, Bootstrap, etc. (recommended: true)
- **minConfidence**: Result filtering
  - HIGH = Fewer false positives, high accuracy
  - MEDIUM = Balanced (recommended)
  - LOW = More results, may include false positives

## 📤 Output Format

Each finding includes:

```json
{
  "severity": "CRITICAL",
  "type": "AWS Access Key",
  "description": "AWS Access Key ID detected",
  "match": "AKIAIOSFODNN7EXAMPLE",
  "source_file": "https://example.com/config.js",
  "line_number": 45,
  "context": "const config = { awsKey: 'AKIAIOSFODNN7EXAMPLE' }",
  "recommendation": "🚨 Rotate AWS credentials immediately via IAM console.",
  "confidence": "HIGH",
  "timestamp": "2025-11-27T12:30:45"
}
```

### Summary Report

The last entry in the dataset is a summary:

```json
{
  "type": "SCAN_SUMMARY",
  "data": {
    "scan_info": {
      "target_url": "https://example.com",
      "scan_completed": "2025-11-27T12:35:00"
    },
    "statistics": {
      "scan_duration_seconds": 45.67,
      "urls_crawled": 25,
      "js_files_analyzed": 42,
      "total_findings": 15
    },
    "summary": {
      "critical_findings": 2,
      "high_findings": 5,
      "total_findings": 15
    }
  }
}
```

## 🎯 How It Works

1. **Crawling**: Starts from your target URL and crawls links up to specified depth
2. **JS Discovery**: Finds all JavaScript resources:
   - Parses HTML for `<script>` tags
   - Extracts inline JavaScript
   - Discovers hidden JS files via regex
3. **Smart Filtering**: Skips common libraries (jQuery, Bootstrap, etc.)
4. **Pattern Matching**: Scans code with 30+ regex patterns
5. **Validation**: Each finding is validated to reduce false positives
6. **Confidence Scoring**: Assigns HIGH/MEDIUM/LOW confidence
7. **Reporting**: Outputs clean JSON with actionable recommendations

## 💡 Best Practices

1. **Start with depth 2** - Good balance of coverage vs speed
2. **Enable library filtering** - Reduces noise from third-party code
3. **Use MEDIUM confidence** - Best accuracy/coverage balance
4. **Review CRITICAL findings first** - Immediate security risks
5. **Check context** - Verify findings aren't false positives

## ⚠️ Important Notes

- This tool is for **security research and authorized testing only**
- Only scan websites you own or have permission to test
- Some findings may be false positives - always verify
- Large websites may take several minutes to scan
- Rate limiting may occur on some websites

## 🔧 Troubleshooting

**No results found?**
- Check if website blocks automated tools
- Try increasing maxDepth
- Verify URLs are accessible

**Too many false positives?**
- Set minConfidence to "HIGH"
- Enable filterCommonLibraries
- Disable includeCdn

**Scan taking too long?**
- Reduce maxDepth to 1
- Enable filterCommonLibraries
- Scan specific pages instead of entire site
