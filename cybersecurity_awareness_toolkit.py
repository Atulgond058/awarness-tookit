"""
Cybersecurity Awareness Toolkit
Author: Atul Gond

A defensive, educational command-line tool with:
1. Password strength feedback (password is not stored or transmitted).
2. Basic offline URL risk indicators for security awareness.
3. CSV sample dataset analysis.

This is an educational heuristic tool, not a substitute for professional security tools.

Run:
    python cybersecurity_awareness_toolkit.py
    python cybersecurity_awareness_toolkit.py --url https://example.com
    python cybersecurity_awareness_toolkit.py --password
    python cybersecurity_awareness_toolkit.py --dataset sample_urls.csv
"""

import argparse
import csv
import getpass
import re
from pathlib import Path
from urllib.parse import urlparse

DEFAULT_DATASET = Path(__file__).with_name("sample_urls.csv")

SUSPICIOUS_TERMS = {
    "login", "verify", "account", "secure", "update", "password",
    "wallet", "banking", "confirm", "bonus", "free", "gift"
}
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly"
}


def assess_password(password):
    """Return a strength label and practical feedback without retaining the password."""
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
    common = {"password", "password123", "12345678", "qwerty123", "admin123"}
    if password.lower() in common:
        score = 0
        feedback.append("Avoid common or easily guessed passwords.")
    if score >= 5:
        label = "Strong"
    elif score >= 3:
        label = "Moderate"
    else:
        label = "Weak"
    if not feedback:
        feedback.append("Good composition. Use a unique password for every account and consider a password manager.")
    return label, feedback


def inspect_url(url):
    """Identify basic URL warning signs using offline heuristics only."""
    candidate = url.strip()
    if not candidate:
        return {"url": url, "risk": "Unknown", "flags": ["No URL supplied"]}
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

    high_signal = any(
        marker in " ".join(flags).lower()
        for marker in ("missing or invalid", "contains @", "ip address", "unusually many")
    )
    if high_signal or len(flags) >= 4:
        risk = "High"
    elif len(flags) >= 2:
        risk = "Caution"
    else:
        risk = "Lower apparent risk"

    if not flags:
        flags.append("No listed warning signs detected by this simple checker.")
    return {"url": candidate, "risk": risk, "flags": flags}


def analyze_dataset(path):
    """Read a sample URL CSV and return basic heuristic results."""
    results = []
    with open(path, "r", newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames or "URL" not in reader.fieldnames:
            raise ValueError("Dataset must contain a column named URL.")
        for row in reader:
            result = inspect_url(row.get("URL", ""))
            result["example_label"] = row.get("ExampleLabel", "Unlabelled")
            results.append(result)
    return results


def print_url_result(result):
    print(f"\nURL: {result['url']}")
    print(f"Assessment: {result['risk']}")
    for flag in result["flags"]:
        print(f"  - {flag}")
    print("Reminder: This is a heuristic only. Do not enter credentials on a site you do not trust.")


def main():
    parser = argparse.ArgumentParser(description="A defensive cybersecurity awareness toolkit.")
    parser.add_argument("--url", help="Inspect a URL using offline warning-sign heuristics.")
    parser.add_argument("--password", action="store_true", help="Interactively check password composition.")
    parser.add_argument("--dataset", help="Analyze URLs from a CSV file (default sample_urls.csv).")
    args = parser.parse_args()

    if args.password:
        password = getpass.getpass("Enter a test password (input is hidden and not saved): ")
        label, feedback = assess_password(password)
        print(f"\nPassword composition assessment: {label}")
        for item in feedback:
            print(f"  - {item}")
        print("Note: This checks composition only; it does not check breach databases.")
        return

    if args.url:
        print_url_result(inspect_url(args.url))
        return

    dataset_path = Path(args.dataset) if args.dataset else DEFAULT_DATASET
    try:
        results = analyze_dataset(dataset_path)
    except (OSError, ValueError) as exc:
        raise SystemExit(f"Error: {exc}")

    print("\nCYBERSECURITY AWARENESS TOOLKIT — SAMPLE URL REVIEW")
    print("=" * 72)
    for result in results:
        label = result.get("example_label", "Unlabelled")
        print(f"\nExample category: {label}")
        print_url_result(result)
    print("\nSafety guidance:")
    print("- Check the exact domain spelling before signing in.")
    print("- Do not trust a link solely because it uses HTTPS.")
    print("- Navigate to important services using a saved bookmark or official app.")
    print("- Report suspected phishing through your organization's approved channel.")


if __name__ == "__main__":
    main()
