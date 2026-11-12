from urllib.parse import urlparse
import re


def extract_features(url):
    # Add scheme if missing
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    hostname = parsed.netloc
    path = parsed.path

    features = [
        len(url),                              # URL length
        len(hostname),                         # Domain length
        len(path),                             # Path length
        url.count("."),                        # Number of dots
        url.count("-"),                        # Number of hyphens
        url.count("@"),                        # @ symbol
        url.count("?"),                        # ?
        url.count("="),                        # =
        url.count("&"),                        # &
        url.count("/"),                        # /
        sum(c.isdigit() for c in url),         # digits
        sum(c.isalpha() for c in url),         # letters
        1 if "https" in url.lower() else 0,    # HTTPS
        1 if "@" in url else 0,               # @ present
        1 if re.search(r"\d+\.\d+\.\d+\.\d+", hostname) else 0
    ]

    return features