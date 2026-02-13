import requests

def test_sql(url):
    payload = "' OR '1'='1"
    try:
        r = requests.get(url + payload, timeout=3)
        if "sql" in r.text.lower():
            return "⚠ High Risk"
        return "✔ Safe"
    except:
        return "Error"

def test_xss(url):
    payload = "<script>alert('XSS')</script>"
    try:
        r = requests.get(url + payload, timeout=3)
        if payload in r.text:
            return "⚠ High Risk"
        return "✔ Safe"
    except:
        return "Error"

def check_headers(url):
    try:
        r = requests.get(url, timeout=3)
        if "Content-Security-Policy" not in r.headers:
            return "⚠ Missing Security Headers"
        return "✔ Secure"
    except:
        return "Error"

def scan_website(url):
    return {
        "sql": test_sql(url),
        "xss": test_xss(url),
        "headers": check_headers(url)
    }
