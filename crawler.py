import requests
import urllib3
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def crawl(url, max_depth=2):
    visited = set()
    endpoints = []

    def _crawl(current_url, depth):
        if depth > max_depth or current_url in visited:
            return

        visited.add(current_url)

        try:
            print(f"[CRAWL] Visiting: {current_url}")

            response = requests.get(
                current_url,
                timeout=10,
                verify=False
            )

            soup = BeautifulSoup(response.text, "html.parser")

            endpoints.append(current_url)

            for link in soup.find_all("a", href=True):
                full_url = urljoin(current_url, link["href"])

                if urlparse(full_url).netloc == urlparse(url).netloc:
                    _crawl(full_url, depth + 1)

            for form in soup.find_all("form"):
                action = form.get("action")
                method = form.get("method", "get").upper()

                inputs = []

                for input_tag in form.find_all("input"):
                    name = input_tag.get("name")
                    if name:
                        inputs.append(name)

                endpoints.append({
                    "url": urljoin(current_url, action) if action else current_url,
                    "method": method,
                    "inputs": inputs
                })

        except Exception as e:
            print(f"[-] Crawl error on {current_url}: {e}")

    _crawl(url, 0)

    return endpoints
