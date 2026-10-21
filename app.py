from flask import Flask, render_template, request, jsonify
import re
from urllib.parse import urlparse
import csv
import io

app = Flask(__name__)

SUSPICIOUS_TERMS = {
    "login", "verify", "account", "secure", "update", "password",
    "wallet", "banking", "confirm", "bonus", "free", "gift"
}
SHORTENER_DOMAINS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly"}

def assess_password(password):
    score = 0
    feedback = []
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        feedback.append("Use at least 12 characters where the service allows it.")
    if re.search(r"[a-z]", password) and re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("Mix uppercase and lowercase letters.")
    if re.search(r"\d", password):
        score += 1
    else:
        feedback.append("Include numbers if appropriate.")
    if re.search(r"[^A-Za-z0-9]", password):
        score += 1
    else:
        feedback.append("Consider symbols if the service supports them.")
    if password.lower() in {"password", "password123", "12345678", "qwerty123", "admin123"}:
        score = 0
        feedback.append("Avoid common or easily guessed passwords.")
    label = "Strong" if score >= 5 else "Moderate" if score >= 3 else "Weak"
    if not feedback:
        feedback.append("Good composition. Use a unique password for every account and consider a password manager.")
    return label, feedback

def inspect_url(url):
    candidate = (url or "").strip()
    if not candidate:
        return {"url": candidate, "risk": "Unknown", "flags": ["No URL supplied"]}
    normalized = candidate if "://" in candidate else "http://" + candidate
    try:
        parsed = urlparse(normalized)
        host = (parsed.hostname or "").lower().rstrip(".")
    except ValueError:
        return {"url": candidate, "risk": "High", "flags": ["URL could not be parsed safely"]}
    flags = []
    if not host:
        flags.append("Missing or invalid hostname")
    if parsed.scheme.lower() != "https":
        flags.append("Does not use HTTPS (this alone does not prove a site is malicious)")
    if "@" in parsed.netloc:
        flags.append("Contains @ in the authority section")
    if host and re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host):
        flags.append("Uses an IP address instead of a recognizable domain")
    if host.count(".") >= 4:
        flags.append("Unusually many subdomain levels")
    if any(term in (host + parsed.path.lower()) for term in SUSPICIOUS_TERMS):
        flags.append("Contains a term sometimes used in deceptive messages")
    if host in SHORTENER_DOMAINS:
        flags.append("Uses a URL-shortening service; destination is obscured")
    if len(candidate) > 100:
        flags.append("Unusually long URL")
    if "-" in host:
        flags.append("Domain contains hyphens; review carefully")
    high_signal = any(marker in " ".join(flags).lower() for marker in
                      ("missing or invalid", "contains @", "ip address", "unusually many"))
    risk = "High" if high_signal or len(flags) >= 4 else "Caution" if len(flags) >= 2 else "Lower apparent risk"
    if not flags:
        flags.append("No listed warning signs detected by this simple checker.")
    return {"url": candidate, "risk": risk, "flags": flags}

@app.get("/")
def home():
    return render_template("index.html")

@app.post("/api/url")
def url_check():
    data = request.get_json(silent=True) or {}
    url = str(data.get("url", ""))[:2048]
    return jsonify(inspect_url(url))

@app.post("/api/password")
def password_check():
    data = request.get_json(silent=True) or {}
    password = str(data.get("password", ""))[:512]
    label, feedback = assess_password(password)
    # The password is processed in memory only and is never logged or stored by this app.
    return jsonify({"label": label, "feedback": feedback})

@app.post("/api/dataset")
def dataset_check():
    if "file" not in request.files:
        return jsonify({"error": "Please choose a CSV file."}), 400
    file = request.files["file"]
    if not file.filename.lower().endswith(".csv"):
        return jsonify({"error": "Please upload a .csv file."}), 400
    raw = file.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        return jsonify({"error": "CSV must be smaller than 1 MB."}), 400
    try:
        reader = csv.DictReader(io.StringIO(raw.decode("utf-8-sig")))
        if not reader.fieldnames or "URL" not in reader.fieldnames:
            return jsonify({"error": "CSV must contain a column named URL."}), 400
        results = []
        for index, row in enumerate(reader):
            if index >= 200:
                break
            result = inspect_url(row.get("URL", ""))
            result["example_label"] = row.get("ExampleLabel", "Unlabelled")
            results.append(result)
        return jsonify({"results": results})
    except (UnicodeDecodeError, csv.Error):
        return jsonify({"error": "Could not read CSV. Save it as UTF-8 CSV and try again."}), 400

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
