import requests
import re

def is_valid_url(url):
    """
    Validate URL format
    """
    regex = re.compile(
        r'^(http|https)://'  # http:// or https://
        r'([a-zA-Z0-9.-]+)'  # domain
        r'(\.[a-zA-Z]{2,})'  # .com, .org etc
        r'(:[0-9]+)?'        # optional port
        r'(\/.*)?$'          # path
    )
    return re.match(regex, url)


def scan_url(url):
    """
    Scan URL and return security result
    """

    # Check if URL is empty
    if not url:
        return "Invalid URL ❌"

    # Add https if missing
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    # Validate URL format
    if not is_valid_url(url):
        return "Invalid URL Format ❌"

    try:
        response = requests.get(url, timeout=5)

        # Safe if status 200
        if response.status_code == 200:
            return "Safe ✅"

        # Suspicious if other status
        else:
            return "Suspicious ⚠️"

    except requests.exceptions.Timeout:
        return "Timeout – Possibly Suspicious ⚠️"

    except requests.exceptions.ConnectionError:
        return "Connection Failed – Malicious ❌"

    except Exception:
        return "Error Occurred ❌"
