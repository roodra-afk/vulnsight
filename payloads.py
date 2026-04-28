SQLI_PAYLOADS = [
    "'",
    "' OR '1'='1",
    "' OR SLEEP(5)-- "
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>"
]
