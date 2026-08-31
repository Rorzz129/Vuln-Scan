import requests


def request_http(target: str) -> requests.Response | None:
    protocols = [
        "https",
        "http"
    ]
    for protocol in protocols:
        url = f"{protocol}://{target}"
        try:
            response = requests.get(
                url,
                timeout=10,
                allow_redirects=True
            )
            return response
        except requests.RequestException:
            continue
    return None

def scan_http(target: str) -> dict:
    response = request_http(target)
    if response is None:
        return {}
    cookies = {}

    for cookie in response.cookies:
        cookies[cookie.name] = cookie.value

    result = {
        "url": response.url,
        "status_code": response.status_code,
        "headers": dict(response.headers),
        "cookies": cookies,
        "html": response.text
    }
    return result

if __name__ == "__main__":

    result = scan_http("example.com")

    if not result:
        print("[!] HTTP request failed")

    else:

        print(f"[+] URL: {result['url']}")
        print(f"[+] Status: {result['status_code']}")

        print("\n[+] Headers:")

        for name, value in result["headers"].items():
            print(f"  {name}: {value}")

        print("\n[+] Cookies:")

        for name, value in result["cookies"].items():
            print(f"  {name}: {value}")