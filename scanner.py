import requests
import time
import urllib3
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from payloads import SQLI_PAYLOADS, XSS_PAYLOADS

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def inject_payload(url, param, payload):
    parsed = urlparse(url)
    query = parse_qs(parsed.query)

    query[param] = payload

    new_query = urlencode(query, doseq=True)

    return urlunparse(parsed._replace(query=new_query))


def scan(endpoints):
    findings = []
    scanned_params = set()

    # URL Parameter Scanning
    for ep in endpoints:
        if isinstance(ep, str) and "?" in ep:
            parsed = urlparse(ep)
            params = parse_qs(parsed.query)

            for param in params:
                signature = f"{parsed.path}:{param}"

                if signature in scanned_params:
                    continue

                scanned_params.add(signature)

                for payload in SQLI_PAYLOADS:
                    test_url = inject_payload(ep, param, payload)

                    try:
                        start = time.time()
                        print(f"[SQLi] Testing {param} on {parsed.path}")

                        response = requests.get(
                            test_url,
                            timeout=5,
                            verify=False
                        )

                        delay = time.time() - start

                        if "sql" in response.text.lower() or "syntax" in response.text.lower():
                            findings.append({
                                "type": "Possible SQL Injection",
                                "url": test_url,
                                "param": param,
                                "payload": payload,
                                "reason": "SQL error message detected"
                            })

                        elif delay > 4 and "SLEEP" in payload.upper():
                            findings.append({
                                "type": "Possible Time-Based SQL Injection",
                                "url": test_url,
                                "param": param,
                                "payload": payload,
                                "reason": f"Delayed response ({delay:.2f}s)"
                            })

                    except Exception:
                        pass

                for payload in XSS_PAYLOADS:
                    test_url = inject_payload(ep, param, payload)

                    try:
                        print(f"[XSS] Testing {param} on {parsed.path}")

                        response = requests.get(
                            test_url,
                            timeout=5,
                            verify=False
                        )

                        if payload in response.text:
                            findings.append({
                                "type": "Possible Reflected XSS",
                                "url": test_url,
                                "param": param,
                                "payload": payload,
                                "reason": "Payload reflected in response"
                            })

                    except Exception:
                        pass

    # Form Scanning
    scanned_forms = set()

    for ep in endpoints:
        if isinstance(ep, dict):
            form_url = ep["url"]
            method = ep["method"]
            inputs = ep["inputs"]

            form_signature = f"{form_url}:{method}:{','.join(sorted(inputs))}"

            if form_signature in scanned_forms:
                continue

            scanned_forms.add(form_signature)

            for param in inputs:

                for payload in SQLI_PAYLOADS:
                    data = {param: payload}

                    try:
                        print(f"[FORM SQLi] Testing {param} on {form_url}")

                        start = time.time()

                        if method == "POST":
                            response = requests.post(
                                form_url,
                                data=data,
                                timeout=5,
                                verify=False
                            )
                        else:
                            response = requests.get(
                                form_url,
                                params=data,
                                timeout=5,
                                verify=False
                            )

                        delay = time.time() - start

                        if "sql" in response.text.lower() or "syntax" in response.text.lower():
                            findings.append({
                                "type": "Possible Form SQL Injection",
                                "url": form_url,
                                "param": param,
                                "payload": payload,
                                "reason": "SQL error message detected"
                            })

                        elif delay > 4 and "SLEEP" in payload.upper():
                            findings.append({
                                "type": "Possible Time-Based Form SQL Injection",
                                "url": form_url,
                                "param": param,
                                "payload": payload,
                                "reason": f"Delayed response ({delay:.2f}s)"
                            })

                    except Exception:
                        pass

                for payload in XSS_PAYLOADS:
                    data = {param: payload}

                    try:
                        print(f"[FORM XSS] Testing {param} on {form_url}")

                        if method == "POST":
                            response = requests.post(
                                form_url,
                                data=data,
                                timeout=5,
                                verify=False
                            )
                        else:
                            response = requests.get(
                                form_url,
                                params=data,
                                timeout=5,
                                verify=False
                            )

                        if payload in response.text:
                            findings.append({
                                "type": "Possible Form Reflected XSS",
                                "url": form_url,
                                "param": param,
                                "payload": payload,
                                "reason": "Payload reflected in response"
                            })

                    except Exception:
                        pass

    return findings
