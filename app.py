from flask import Flask, render_template, request
import re
import whois
from datetime import datetime

app = Flask(__name__)

def is_ip_address(url):
    ip_pattern = re.compile(
        r'((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
    )
    return bool(ip_pattern.search(url))

def get_domain_age(domain):
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date is None:
            return 0

        today = datetime.now()
        age = (today - creation_date).days
        return age
    except:
        return 0

def extract_domain(url):
    domain = re.sub(r"https?://", "", url)
    domain = domain.split("/")[0]
    return domain

def check_phishing(url):
    risk_score = 0
    reasons = []

    # URL Length
    if len(url) > 75:
        risk_score += 1
        reasons.append("URL is too long")

    # Suspicious Keywords
    suspicious_words = [
        "login", "verify", "update", "secure", "bank", "free",
        "reward", "confirm", "account", "signin", "webscr", "paypal"
    ]

    for word in suspicious_words:
        if word in url.lower():
            risk_score += 1
            reasons.append(f"Suspicious keyword found: {word}")
            break

    # HTTPS
    if not url.startswith("https"):
        risk_score += 1
        reasons.append("No HTTPS detected")

    # IP in URL
    if is_ip_address(url):
        risk_score += 1
        reasons.append("IP address used instead of domain name")

    # Dots Count
    if url.count(".") > 4:
        risk_score += 1
        reasons.append("Too many dots in URL")

    # Domain Age
    domain = extract_domain(url)
    age = get_domain_age(domain)

    if age != 0 and age < 180:
        risk_score += 1
        reasons.append(f"Domain is new (Age: {age} days)")

    if risk_score <= 1:
        verdict = "SAFE"
        color = "green"
    elif risk_score == 2:
        verdict = "SUSPICIOUS"
        color = "orange"
    else:
        verdict = "PHISHING"
        color = "red"

    return verdict, color, risk_score, reasons

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    if request.method == "POST":
        url = request.form.get("url")
        verdict, color, score, reasons = check_phishing(url)
        result = {
            "url": url,
            "verdict": verdict,
            "color": color,
            "score": score,
            "reasons": reasons
        }

    return render_template("index.html", result=result)

if __name__ == "__main__":
    app.run(debug=True)
