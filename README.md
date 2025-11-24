# 🛡️ Website Security Auditor & JS Secrets Scanner

[![Apify](https://img.shields.io/badge/Apify-Actor-green)](https://apify.com/)
[![Python](https://img.shields.io/badge/Python-3.9+-blue)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-lightgrey)](LICENSE)

**A high-speed, asynchronous static analysis tool designed to help developers and security teams identify exposed secrets, API keys, and sensitive configuration data hidden within client-side JavaScript files.**

---

## 🚀 Why this tool?

Modern web applications rely heavily on JavaScript. Often, developers accidentally commit sensitive keys (Google Maps API, AWS Credentials, Slack Tokens) or sensitive logic into client-side code. 

This Actor crawls a target website, extracts all internal and external JavaScript files, and performs a deep regex-based audit to report potential security leaks before malicious actors find them.

### 🌟 Key Features
* **⚡ Blazing Fast:** Built on Python `asyncio` and `aiohttp` for concurrent scanning of hundreds of scripts.
* **🔍 Deep Inspection:** Scans inline scripts, external JS files, and CDN resources.
* **🛡️ Signature Based:** Detects 80+ types of secrets including:
    * Google API Keys & Firebase Configs
    * AWS Access Keys & Secrets
    * Slack, Stripe, & GitHub Tokens
    * Private Keys (RSA/DSA)
    * Database Connection Strings (MongoDB, Postgres)
* **📉 Low False Positives:** Intelligent context analysis to ignore example code and comments.
* **JSON Output:** Clean, structured data ready for integration with other DevSecOps tools.

---

## 🛠️ Input Parameters

The Actor takes the following inputs:

| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `startUrls` | Array | `[]` | List of target URLs to scan (e.g., `https://example.com`). |
| `maxDepth` | Integer | `2` | How deep the crawler should traverse links (1 = scan single page). |
| `includeCdn` | Boolean | `false` | If true, scans external scripts (e.g., hosted on AWS S3, Cloudflare). |

---

## 📊 Sample Output

The tool provides findings in a structured JSON format:

```json
[
  {
    "finding_type": "Google API Key",
    "severity": "CRITICAL",
    "match": "AIzaSyBwQcjgmXUAsw5r4FZXO5t8_EZ_aUm_TGE",
    "source_url": "[https://example.com/assets/main.bundle.js](https://example.com/assets/main.bundle.js)",
    "context": "apiKey: \"AIzaSyBwQcjgmXUAsw5r4FZXO5t8_EZ_aUm_TGE\", authDomain:...",
    "hash": "5d41402abc4b2a76b9719d911017c592"
  },
  {
    "finding_type": "Potential XSS Sink",
    "severity": "MEDIUM",
    "match": ".innerHTML =",
    "source_url": "[https://example.com/js/ui-utils.js](https://example.com/js/ui-utils.js)",
    "context": "document.getElementById('app').innerHTML = userInput;",
    "hash": "a1b2c3d4e5f6..."
  }
]
