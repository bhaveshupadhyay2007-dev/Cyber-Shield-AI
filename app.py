from flask import Flask, render_template, request
from src.predict import analyze_url
from scan_history import save_scan, load_history, get_statistics
import re

app = Flask(__name__)


def force_suspicious_block(url, result):
    url_lower = url.lower()
    strong_indicators = 0

    # IP address used directly in URL
    if re.search(r"https?://\d{1,3}(\.\d{1,3}){3}", url_lower):
        strong_indicators += 1

    # Suspicious security-related words
    suspicious_words = [
        "login",
        "verify",
        "verification",
        "account",
        "password",
        "confirm",
        "secure-login",
        "security-check",
        "update-account",
        "signin",
        "credential"
    ]

    for word in suspicious_words:
        if word in url_lower:
            strong_indicators += 1

    # High-risk TLDs
    risky_tlds = [
        ".tk",
        ".ml",
        ".ga",
        ".cf",
        ".gq"
    ]

    for tld in risky_tlds:
        if tld in url_lower:
            strong_indicators += 1

    # HTTP instead of HTTPS
    if url_lower.startswith("http://"):
        strong_indicators += 1

    # @ symbol in URL
    if "@" in url_lower:
        strong_indicators += 1

    # Very long URL
    if len(url) > 100:
        strong_indicators += 1

    return strong_indicators >= 3


def normalize_result(result):
    """
    Makes the prediction response consistent.

    predict.py currently returns the classification
    using the key 'result'. The rest of the application
    uses 'classification'.

    This function keeps both keys available.
    """

    if not isinstance(result, dict):
        return result

    classification = result.get("classification")

    if not classification:
        classification = result.get("result", "")

    classification = str(classification).upper().strip()

    if classification:
        result["classification"] = classification
        result["result"] = classification

    return result


@app.route("/", methods=["GET", "POST"])
def home():

    result = None

    if request.method == "POST":

        url = request.form.get("url", "").strip()

        if url:

            # Analyze URL
            result = analyze_url(url)

            # Make response fields consistent
            result = normalize_result(result)

            classification = str(
                result.get("classification", "")
            ).upper()

            action = str(
                result.get("action", "")
            ).upper()

            try:
                risk_score = float(
                    result.get("risk_score", 0)
                )
            except (TypeError, ValueError):
                risk_score = 0

            # Additional hard-block protection
            hard_block = force_suspicious_block(
                url,
                result
            )

            # Final blocking decision
            if (
                classification == "SUSPICIOUS"
                or action == "BLOCK"
                or risk_score >= 65
                or hard_block
            ):

                result["classification"] = "SUSPICIOUS"
                result["result"] = "SUSPICIOUS"
                result["action"] = "BLOCK"

                save_scan(result)

                return render_template(
                    "blocked.html",
                    result=result
                )

            # Normal result
            save_scan(result)

    statistics = get_statistics()

    return render_template(
        "index.html",
        result=result,
        statistics=statistics
    )


@app.route("/blocked")
def blocked():

    url = request.args.get("url", "")

    result = None

    if url:

        result = analyze_url(url)

        # Make response fields consistent
        result = normalize_result(result)

        classification = str(
            result.get("classification", "")
        ).upper()

        action = str(
            result.get("action", "")
        ).upper()

        try:
            risk_score = float(
                result.get("risk_score", 0)
            )
        except (TypeError, ValueError):
            risk_score = 0

        # Apply final blocking logic
        if (
            classification == "SUSPICIOUS"
            or action == "BLOCK"
            or risk_score >= 65
            or force_suspicious_block(url, result)
        ):

            result["classification"] = "SUSPICIOUS"
            result["result"] = "SUSPICIOUS"
            result["action"] = "BLOCK"

    return render_template(
        "blocked.html",
        result=result
    )


@app.route("/history")
def history():

    history_data = load_history()

    statistics = get_statistics()

    return render_template(
        "history.html",
        history=history_data,
        statistics=statistics
    )



@app.route("/robots.txt")
def robots_txt():
    return """User-agent: *
Allow: /

Sitemap: https://cyber-shield-ai-y27s.onrender.com/sitemap.xml
""", 200, {"Content-Type": "text/plain"}


@app.route("/sitemap.xml")
def sitemap_xml():
    return """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
    <url>
        <loc>https://cyber-shield-ai-y27s.onrender.com/</loc>
    </url>
</urlset>""", 200, {"Content-Type": "application/xml"}


if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )