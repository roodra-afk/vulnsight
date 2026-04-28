import argparse
from crawler import crawl
from scanner import scan
from reporter import generate_report

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True, help="Target URL")
    args = parser.parse_args()

    print(f"[+] Starting scan on {args.url}")

    endpoints = crawl(args.url)
    print(f"[+] Found {len(endpoints)} endpoints")
    for ep in endpoints:
        print(ep)

    findings = scan(endpoints)

    generate_report(findings)

if __name__ == "__main__":
    main()
