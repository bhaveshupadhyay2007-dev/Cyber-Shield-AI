import os
import re
import ipaddress
import joblib

from urllib.parse import urlparse

from src.feature_extraction import extract_features
from src.threat_intelligence import check_url


# ============================================================
# CONFIGURATION
# ============================================================

MODEL_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "models",
    "url_model.pkl"
)


# ============================================================
# TRUSTED DOMAINS
# ============================================================

TRUSTED_DOMAINS = {
    "google.com",
    "google.co.in",
    "youtube.com",
    "youtu.be",
    "github.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "amazon.in",
    "linkedin.com",
    "facebook.com",
    "instagram.com",
    "whatsapp.com",
    "openai.com",
    "python.org",
    "pypi.org",
    "mozilla.org",
    "cloudflare.com",
    "stackoverflow.com",
    "wikipedia.org"
}


# ============================================================
# SUSPICIOUS KEYWORDS
# ============================================================

SUSPICIOUS_KEYWORDS = {
    "login": 12,
    "log-in": 12,
    "signin": 12,
    "sign-in": 12,
    "verify": 12,
    "verification": 14,
    "account": 8,
    "account-verification": 15,
    "update": 7,
    "update-account": 15,
    "secure": 6,
    "security": 7,
    "password": 14,
    "passwd": 14,
    "credential": 14,
    "credentials": 14,
    "authenticate": 12,
    "authentication": 12,
    "bank": 15,
    "banking": 15,
    "wallet": 12,
    "crypto": 10,
    "cryptocurrency": 10,
    "payment": 10,
    "payments": 10,
    "invoice": 8,
    "refund": 8,
    "confirm": 10,
    "confirmation": 10,
    "unlock": 10,
    "activate": 8,
    "suspend": 12,
    "suspended": 12,
    "recover": 10,
    "recovery": 10,
    "reset": 10,
    "urgent": 8,
    "alert": 7,
    "security-check": 15,
    "validate": 10,
    "validation": 10,
    "claim": 7,
    "reward": 7,
    "prize": 7,
    "winner": 7,
    "free": 5,
    "bonus": 5,
    "gift": 5
}


# ============================================================
# RISKY TLDs
# ============================================================

RISKY_TLDS = {
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".gq",
    ".top",
    ".click",
    ".work",
    ".zip",
    ".download",
    ".stream",
    ".buzz",
    ".cam",
    ".country"
}


# ============================================================
# URL SHORTENERS
# ============================================================

SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rb.gy",
    "shorturl.at"
}


# ============================================================
# MODEL LOADING
# ============================================================

model = None

try:
    if os.path.exists(MODEL_PATH):
        model = joblib.load(MODEL_PATH)
except Exception as e:
    print("Warning: Could not load ML model:", e)
    model = None


# ============================================================
# BASIC URL HELPERS
# ============================================================

def normalize_url(url):
    """
    Adds http:// when the user enters a URL without a scheme.
    """
    url = str(url).strip()

    if not url:
        return ""

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    return url


def get_hostname(url):
    """
    Extract hostname from URL.
    """
    try:
        parsed = urlparse(normalize_url(url))
        return (parsed.hostname or "").lower()
    except Exception:
        return ""


def get_root_domain(hostname):
    """
    Basic root-domain extraction.
    """
    hostname = hostname.lower().strip(".")

    if not hostname:
        return ""

    parts = hostname.split(".")

    if len(parts) >= 2:
        return ".".join(parts[-2:])

    return hostname


def is_ip_address(hostname):
    """
    Checks whether hostname is an IPv4/IPv6 address.
    """
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def is_trusted_domain(hostname):
    """
    Checks exact trusted root domain.
    """
    hostname = hostname.lower().strip(".")

    for domain in TRUSTED_DOMAINS:
        if hostname == domain or hostname.endswith("." + domain):
            return True

    return False


def is_shortener(hostname):
    hostname = hostname.lower().strip(".")

    for domain in SHORTENER_DOMAINS:
        if hostname == domain:
            return True

    return False


def has_risky_tld(hostname):
    hostname = hostname.lower()

    return any(
        hostname.endswith(tld)
        for tld in RISKY_TLDS
    )


# ============================================================
# HEURISTIC ANALYSIS
# ============================================================

def heuristic_analysis(url):

    url = normalize_url(url)

    parsed = urlparse(url)

    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""

    url_lower = url.lower()

    score = 0
    indicators = []

    def add_score(points, message):
        nonlocal score

        score += points

        if message not in indicators:
            indicators.append(message)

    # --------------------------------------------------------
    # HTTP instead of HTTPS
    # --------------------------------------------------------

    if url_lower.startswith("http://"):
        add_score(
            8,
            "Uses HTTP instead of HTTPS"
        )

    # --------------------------------------------------------
    # IP ADDRESS
    # --------------------------------------------------------

    if hostname and is_ip_address(hostname):
        add_score(
            25,
            "Uses an IP address instead of a domain"
        )

    # --------------------------------------------------------
    # @ SYMBOL
    # --------------------------------------------------------

    if "@" in url:
        add_score(
            25,
            "Contains @ symbol"
        )

    # --------------------------------------------------------
    # VERY LONG URL
    # --------------------------------------------------------

    if len(url) > 120:
        add_score(
            12,
            "Very long URL"
        )
    elif len(url) > 80:
        add_score(
            6,
            "Long URL"
        )

    # --------------------------------------------------------
    # MANY SUBDOMAINS
    # --------------------------------------------------------

    if hostname:
        domain_parts = hostname.split(".")

        if len(domain_parts) >= 5:
            add_score(
                18,
                "Excessive subdomains"
            )
        elif len(domain_parts) == 4:
            add_score(
                7,
                "Multiple subdomains"
            )

    # --------------------------------------------------------
    # MANY HYPHENS
    # --------------------------------------------------------

    hyphen_count = hostname.count("-")

    if hyphen_count >= 3:
        add_score(
            15,
            "Multiple hyphens in domain"
        )
    elif hyphen_count == 2:
        add_score(
            8,
            "Multiple hyphens in domain"
        )

    # --------------------------------------------------------
    # MANY DIGITS
    # --------------------------------------------------------

    digit_count = sum(
        character.isdigit()
        for character in hostname
    )

    if digit_count >= 5:
        add_score(
            10,
            "Unusual number of digits in domain"
        )

    # --------------------------------------------------------
    # ENCODED CHARACTERS
    # --------------------------------------------------------

    if "%" in url:
        add_score(
            8,
            "Contains encoded URL characters"
        )

    # --------------------------------------------------------
    # DOUBLE SLASH IN PATH
    # --------------------------------------------------------

    if "//" in path:
        add_score(
            8,
            "Contains unusual double slash"
        )

    # --------------------------------------------------------
    # SUSPICIOUS KEYWORDS
    # --------------------------------------------------------

    keyword_score = 0
    matched_keywords = []

    for keyword, points in SUSPICIOUS_KEYWORDS.items():

        if keyword in url_lower:

            keyword_score += points
            matched_keywords.append(keyword)

    if matched_keywords:

        # Prevent keywords alone from producing
        # an unlimited score.
        keyword_score = min(keyword_score, 40)

        add_score(
            keyword_score,
            "Suspicious keywords: " +
            ", ".join(matched_keywords[:6])
        )

    # --------------------------------------------------------
    # MULTIPLE CREDENTIAL / SECURITY KEYWORDS
    # --------------------------------------------------------

    security_words = [
        "login",
        "signin",
        "verify",
        "verification",
        "account",
        "password",
        "credential",
        "security",
        "secure",
        "confirm"
    ]

    security_matches = [
        word
        for word in security_words
        if word in url_lower
    ]

    if len(security_matches) >= 3:

        add_score(
            20,
            "Multiple credential/security keywords"
        )

    elif len(security_matches) >= 2:

        add_score(
            10,
            "Multiple credential/security keywords"
        )

    # --------------------------------------------------------
    # BRAND + SECURITY KEYWORD PATTERN
    # --------------------------------------------------------

    brands = [
        "paypal",
        "microsoft",
        "apple",
        "amazon",
        "google",
        "facebook",
        "instagram",
        "linkedin",
        "netflix",
        "whatsapp",
        "bank"
    ]

    brand_found = None

    for brand in brands:

        if brand in url_lower:
            brand_found = brand
            break

    if brand_found:

        brand_security_words = [
            "login",
            "signin",
            "verify",
            "security",
            "account",
            "password",
            "confirm",
            "secure",
            "payment"
        ]

        brand_security_matches = [
            word
            for word in brand_security_words
            if word in url_lower
        ]

        if len(brand_security_matches) >= 2:

            add_score(
                30,
                "Brand name combined with security keywords"
            )

        elif len(brand_security_matches) == 1:

            add_score(
                15,
                "Brand name combined with security keyword"
            )

    # --------------------------------------------------------
    # RISKY TLD
    # --------------------------------------------------------

    if has_risky_tld(hostname):

        add_score(
            20,
            "Uses a higher-risk top-level domain"
        )

    # --------------------------------------------------------
    # URL SHORTENER
    # --------------------------------------------------------

    if is_shortener(hostname):

        add_score(
            18,
            "Uses a URL shortening service"
        )

    # --------------------------------------------------------
    # PUNYCODE
    # --------------------------------------------------------

    if "xn--" in hostname:

        add_score(
            20,
            "Contains Punycode domain"
        )

    # --------------------------------------------------------
    # QUERY PARAMETERS
    # --------------------------------------------------------

    if query:

        if query.count("=") >= 3:

            add_score(
                10,
                "Contains many query parameters"
            )

        elif query:

            add_score(
                4,
                "Contains query parameters"
            )

    # --------------------------------------------------------
    # DANGEROUS FILE EXTENSIONS
    # --------------------------------------------------------

    dangerous_extensions = [
        ".exe",
        ".scr",
        ".bat",
        ".cmd",
        ".msi",
        ".apk",
        ".jar",
        ".vbs",
        ".ps1"
    ]

    for extension in dangerous_extensions:

        if extension in url_lower:

            add_score(
                25,
                "Contains potentially dangerous file extension: " +
                extension
            )

    # --------------------------------------------------------
    # CREDENTIAL-LIKE URL
    # --------------------------------------------------------

    credential_pattern = re.search(
        r"(login|signin|verify|account|password|credential).*(login|signin|verify|account|password|credential)",
        url_lower
    )

    if credential_pattern:

        add_score(
            15,
            "Credential-related URL pattern detected"
        )

    # --------------------------------------------------------
    # MANY DOTS IN PATH
    # --------------------------------------------------------

    if path.count(".") >= 4:

        add_score(
            8,
            "Unusual number of dots in URL path"
        )

    # --------------------------------------------------------
    # UNUSUAL PORT
    # --------------------------------------------------------

    try:

        port = parsed.port

        if port is not None and port not in (80, 443):

            add_score(
                12,
                "Uses an unusual network port"
            )

    except ValueError:

        add_score(
            15,
            "Invalid network port"
        )

    # --------------------------------------------------------
    # SPECIAL CHARACTERS
    # --------------------------------------------------------

    special_count = len(
        re.findall(
            r"[^a-zA-Z0-9:/?&=._%\-]",
            url
        )
    )

    if special_count >= 5:

        add_score(
            10,
            "Contains many unusual special characters"
        )

    # --------------------------------------------------------
    # SUSPICIOUS DOMAIN STRUCTURE
    # --------------------------------------------------------

    if hostname:

        hostname_parts = hostname.split(".")

        for part in hostname_parts:

            if len(part) > 30:

                add_score(
                    10,
                    "Very long domain component"
                )

                break

    # --------------------------------------------------------
    # FINAL SCORE
    # --------------------------------------------------------

    score = min(int(score), 100)

    return {
        "score": score,
        "indicators": indicators
    }


# ============================================================
# MACHINE LEARNING PREDICTION
# ============================================================

def machine_learning_prediction(url):

    if model is None:

        return {
            "prediction": None,
            "model_result": "MODEL_UNAVAILABLE",
            "ml_score": 0,
            "features": [],
            "classes": []
        }

    try:

        features = extract_features(url)

        prediction = model.predict([features])[0]

        classes = list(
            getattr(
                model,
                "classes_",
                []
            )
        )

        ml_score = 0

        # ----------------------------------------------------
        # Probability-based score
        # ----------------------------------------------------

        if hasattr(model, "predict_proba"):

            probabilities = model.predict_proba(
                [features]
            )[0]

            if len(probabilities) > 1:

                # Treat the second class as suspicious
                # when possible.
                if len(classes) >= 2:

                    suspicious_index = 1

                    try:
                        suspicious_index = list(
                            classes
                        ).index(1)

                    except ValueError:

                        suspicious_index = len(
                            probabilities
                        ) - 1

                    ml_score = int(
                        float(
                            probabilities[
                                suspicious_index
                            ]
                        ) * 100
                    )

                else:

                    ml_score = int(
                        max(probabilities) * 100
                    )

        # ----------------------------------------------------
        # Fallback if probability unavailable
        # ----------------------------------------------------

        if ml_score == 0:

            prediction_text = str(
                prediction
            ).lower()

            if prediction_text in {
                "1",
                "true",
                "phishing",
                "malicious",
                "suspicious"
            }:

                ml_score = 80

            else:

                ml_score = 20

        return {
            "prediction": prediction,
            "model_result": str(prediction),
            "ml_score": ml_score,
            "features": features,
            "classes": classes
        }

    except Exception as e:

        return {
            "prediction": None,
            "model_result": "MODEL_ERROR",
            "ml_score": 0,
            "features": [],
            "classes": [],
            "error": str(e)
        }


# ============================================================
# THREAT INTELLIGENCE
# ============================================================

def threat_intelligence_analysis(url):

    try:

        result = check_url(url)

        if not isinstance(result, dict):

            return {
                "available": False,
                "detected": False,
                "score": 0,
                "message": "No threat intelligence result available."
            }

        # ----------------------------------------------------
        # Try common VirusTotal response formats
        # ----------------------------------------------------

        detected = bool(
            result.get("detected", False)
        )

        score = result.get(
            "score",
            result.get(
                "threat_score",
                0
            )
        )

        try:
            score = float(score)
        except (TypeError, ValueError):
            score = 0

        message = result.get(
            "message",
            result.get(
                "result",
                "Threat intelligence checked."
            )
        )

        available = result.get(
            "available",
            True
        )

        return {
            "available": bool(available),
            "detected": detected,
            "score": min(int(score), 100),
            "message": str(message)
        }

    except Exception as e:

        return {
            "available": False,
            "detected": False,
            "score": 0,
            "message": "Threat intelligence unavailable."
        }


# ============================================================
# MAIN URL ANALYSIS
# ============================================================

def analyze_url(url):

    original_url = str(url).strip()

    if not original_url:

        return {
            "url": "",
            "classification": "UNKNOWN",
            "result": "UNKNOWN",
            "action": "CHECK",
            "risk_score": 0,
            "ml_score": 0,
            "heuristic_score": 0,
            "threat_intelligence_score": 0,
            "indicators": [],
            "hostname": "",
            "threat_intelligence": "No URL provided."
        }

    normalized_url = normalize_url(original_url)

    hostname = get_hostname(
        normalized_url
    )

    # --------------------------------------------------------
    # Invalid URL
    # --------------------------------------------------------

    if not hostname:

        return {
            "url": original_url,
            "classification": "SUSPICIOUS",
            "result": "SUSPICIOUS",
            "action": "BLOCK",
            "risk_score": 90,
            "ml_score": 0,
            "heuristic_score": 90,
            "threat_intelligence_score": 0,
            "indicators": [
                "Invalid or malformed URL"
            ],
            "hostname": "",
            "threat_intelligence": "URL could not be parsed."
        }

    # --------------------------------------------------------
    # Heuristic
    # --------------------------------------------------------

    heuristic = heuristic_analysis(
        normalized_url
    )

    heuristic_score = int(
        heuristic["score"]
    )

    indicators = list(
        heuristic["indicators"]
    )

    # --------------------------------------------------------
    # Machine Learning
    # --------------------------------------------------------

    ml = machine_learning_prediction(
        normalized_url
    )

    ml_score = int(
        ml.get("ml_score", 0)
    )

    # --------------------------------------------------------
    # Threat Intelligence
    # --------------------------------------------------------

    ti = threat_intelligence_analysis(
        normalized_url
    )

    ti_score = int(
        ti.get("score", 0)
    )

    ti_detected = bool(
        ti.get("detected", False)
    )

    # --------------------------------------------------------
    # Trusted domain
    # --------------------------------------------------------

    trusted = is_trusted_domain(
        hostname
    )

    # --------------------------------------------------------
    # Base risk score
    # --------------------------------------------------------

    risk_score = (
        (ml_score * 0.45) +
        (heuristic_score * 0.40) +
        (ti_score * 0.15)
    )

    risk_score = int(
        round(risk_score)
    )

    # --------------------------------------------------------
    # Strong heuristic combinations
    # --------------------------------------------------------

    strong_patterns = 0

    url_lower = normalized_url.lower()

    if is_ip_address(hostname):
        strong_patterns += 1

    if "@" in normalized_url:
        strong_patterns += 1

    if has_risky_tld(hostname):
        strong_patterns += 1

    security_terms = [
        "login",
        "signin",
        "verify",
        "password",
        "credential",
        "account",
        "security"
    ]

    security_count = sum(
        1
        for term in security_terms
        if term in url_lower
    )

    if security_count >= 2:
        strong_patterns += 1

    if (
        any(
            brand in url_lower
            for brand in [
                "paypal",
                "microsoft",
                "apple",
                "amazon",
                "google",
                "facebook",
                "instagram",
                "linkedin"
            ]
        )
        and security_count >= 1
    ):
        strong_patterns += 1

    if len(normalized_url) > 120:
        strong_patterns += 1

    # --------------------------------------------------------
    # Strengthen high-confidence suspicious patterns
    # --------------------------------------------------------

    if strong_patterns >= 3:

        risk_score = max(
            risk_score,
            75
        )

    elif strong_patterns >= 2:

        risk_score = max(
            risk_score,
            65
        )

    # --------------------------------------------------------
    # Brand impersonation protection
    # --------------------------------------------------------

    brand_domains = {
        "paypal": "paypal.com",
        "microsoft": "microsoft.com",
        "apple": "apple.com",
        "amazon": "amazon.com",
        "google": "google.com",
        "facebook": "facebook.com",
        "instagram": "instagram.com",
        "linkedin": "linkedin.com"
    }

    for brand, official_domain in brand_domains.items():

        if brand in hostname:

            if not (
                hostname == official_domain
                or hostname.endswith(
                    "." + official_domain
                )
            ):

                if any(
                    word in url_lower
                    for word in [
                        "login",
                        "signin",
                        "verify",
                        "account",
                        "password",
                        "security",
                        "confirm"
                    ]
                ):

                    risk_score = max(
                        risk_score,
                        75
                    )

                    message = (
                        "Possible " +
                        brand.title() +
                        " impersonation"
                    )

                    if message not in indicators:
                        indicators.append(message)

    # --------------------------------------------------------
    # Threat intelligence detection
    # --------------------------------------------------------

    if ti_detected:

        risk_score = max(
            risk_score,
            85
        )

        if "Detected by external threat intelligence" not in indicators:

            indicators.append(
                "Detected by external threat intelligence"
            )

    # --------------------------------------------------------
    # Trusted domain handling
    # --------------------------------------------------------

    if trusted:

        # Trusted domains get a strong reduction,
        # but obvious malicious URL structures
        # are still allowed to raise the risk.
        if strong_patterns < 2 and not ti_detected:

            risk_score = min(
                risk_score,
                15
            )

    # --------------------------------------------------------
    # Final cap
    # --------------------------------------------------------

    risk_score = min(
        max(int(risk_score), 0),
        100
    )

    # --------------------------------------------------------
    # Classification
    # --------------------------------------------------------

    if risk_score >= 70:

        classification = "SUSPICIOUS"
        action = "BLOCK"

    elif risk_score >= 40:

        classification = "WARNING"
        action = "CHECK"

    else:

        classification = "SAFE"
        action = "ALLOW"

    # --------------------------------------------------------
    # Make sure strong phishing patterns are blocked
    # --------------------------------------------------------

    if (
        strong_patterns >= 3
        or ti_detected
    ):

        classification = "SUSPICIOUS"
        action = "BLOCK"

        risk_score = max(
            risk_score,
            70
        )

    # --------------------------------------------------------
    # Threat intelligence message
    # --------------------------------------------------------

    ti_message = str(
        ti.get(
            "message",
            "No external threat intelligence result available."
        )
    )

    # --------------------------------------------------------
    # FINAL RESULT
    # --------------------------------------------------------

    return {
        "url": original_url,

        "classification": classification,

        # Compatibility with older code
        "result": classification,

        "action": action,

        "risk_score": risk_score,

        "ml_score": ml_score,

        "heuristic_score": heuristic_score,

        "threat_intelligence_score": ti_score,

        "indicators": indicators,

        "hostname": hostname,

        "threat_intelligence": ti_message
    }


# ============================================================
# SIMPLE PREDICT FUNCTION
# ============================================================

def predict_url(url):

    result = analyze_url(url)

    return {
        "url": result.get("url", ""),
        "result": result.get(
            "classification",
            result.get("result", "UNKNOWN")
        ),
        "risk_score": result.get(
            "risk_score",
            0
        ),
        "action": result.get(
            "action",
            "CHECK"
        )
    }


# ============================================================
# MODEL VERIFICATION
# ============================================================

def verify_model():

    print("\n" + "=" * 60)
    print("CYBER SHIELD AI - MODEL VERIFICATION")
    print("=" * 60)

    print(
        "Model path:",
        MODEL_PATH
    )

    print(
        "Model loaded:",
        model is not None
    )

    if model is not None:

        print(
            "Model type:",
            type(model).__name__
        )

        print(
            "Classes:",
            getattr(
                model,
                "classes_",
                "Unknown"
            )
        )

        print(
            "Features:",
            getattr(
                model,
                "n_features_in_",
                "Unknown"
            )
        )

    print(
        "VirusTotal:",
        "Available"
        if os.getenv("VIRUSTOTAL_API_KEY")
        else "Not configured"
    )

    test_urls = [

        "https://www.google.com",

        "https://github.com",

        "http://paypal-login-security.com",

        "http://paypal-security-verify-account.tk/login?confirm=password",

        "http://192.168.1.100/login/verify-account?password=123456"
    ]

    print("\nTEST RESULTS")
    print("-" * 60)

    for test_url in test_urls:

        result = analyze_url(
            test_url
        )

        print(
            "\nURL:",
            test_url
        )

        print(
            "Classification:",
            result["classification"]
        )

        print(
            "Action:",
            result["action"]
        )

        print(
            "Risk:",
            result["risk_score"]
        )

        print(
            "ML:",
            result["ml_score"]
        )

        print(
            "Heuristic:",
            result["heuristic_score"]
        )

        print(
            "Indicators:",
            result["indicators"]
        )

    print("\n" + "=" * 60)


# ============================================================
# DIRECT EXECUTION
# ============================================================

if __name__ == "__main__":

    verify_model()