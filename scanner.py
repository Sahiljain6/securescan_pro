import requests

def scan_url(url):
    if not url:
        return "Invalid URL ❌"

    if not url.startswith("http"):
        url = "https://" + url

    try:
        response = requests.get(url, timeout=5)

        if response.status_code == 200:
            return "Safe ✅"
        else:
            return "Suspicious ⚠️"

    except:
        return "Malicious ❌"
