# Aegis

Aegis is a Python-based automated web vulnerability scanner designed to identify common web application vulnerabilities through intelligent crawling and payload-based testing.

---

## Features

- Crawls target websites for URLs and HTML forms
- Extracts GET parameters and form inputs
- Detects potential SQL Injection vulnerabilities
- Detects reflected XSS vulnerabilities
- Supports GET and POST form scanning
- Deduplicates parameters to avoid redundant scans
- Generates structured vulnerability reports

---

## Tech Stack

- Python 3
- Requests
- BeautifulSoup4

---

## Usage

```bash
python main.py --url https://target-site.com
```

---

## Example Output

```text
Type   : Possible Form Reflected XSS
URL    : https://demo.testfire.net/search.jsp
Param  : query
Payload: <script>alert(1)</script>
Reason : Payload reflected in response
```

---

## Disclaimer

This tool is intended for educational purposes and authorized security testing only.

Unauthorized use against systems without permission may violate laws and regulations.
