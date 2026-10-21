# Cybersecurity Awareness Toolkit

**Student:** Atul Gond  
**Project type:** Educational defensive cybersecurity  
**Language:** Python 3

## Project description
This command-line project demonstrates two basic security-awareness tasks:
- **Password composition feedback:** rates a password as Weak, Moderate, or Strong based on length and character variety. The password is entered through hidden terminal input and is not saved or transmitted.
- **Offline URL warning-sign review:** checks a URL for simple indicators such as non-HTTPS scheme, an IP-address hostname, excessive subdomains, suspicious terms, URL shorteners, and unusual length.
- **Sample dataset mode:** reads demonstration URLs from a CSV file and prints a review for each.

This tool is educational only. It does not prove that a URL is safe or malicious, does not visit websites, does not scan networks, and does not check passwords against breach databases.

## Technologies
- Python 3
- Standard library: `argparse`, `csv`, `getpass`, `re`, `urllib.parse`, `pathlib`

## Dataset details
- Included dataset: [`sample_urls.csv`](sample_urls.csv)
- The CSV contains illustrative example URLs for classroom demonstrations. The reserved `example.com` / `example.net` domains and documentation-only IP address are used to avoid presenting the examples as real threat intelligence.
- Columns: `URL`, `ExampleLabel`
- No external dataset is required. If you replace the sample data with public data, check its license and cite its source in your report.

## Requirements
- Python 3.8 or later recommended
- No third-party packages; `requirements.txt` is included for submission.

## Setup and run
1. Extract the ZIP archive.
2. Open Command Prompt or a terminal in this folder.
3. Check Python:
   ```bash
   python --version
   ```
4. Run the sample dataset:
   ```bash
   python cybersecurity_awareness_toolkit.py
   ```
5. Inspect a URL:
   ```bash
   python cybersecurity_awareness_toolkit.py --url https://example.com
   ```
6. Check password composition (use a test password, not a password you currently use):
   ```bash
   python cybersecurity_awareness_toolkit.py --password
   ```
7. Analyze another CSV file:
   ```bash
   python cybersecurity_awareness_toolkit.py --dataset my_urls.csv
   ```

## Limitations
- URL checks are heuristic and can produce false positives and false negatives.
- HTTPS indicates an encrypted connection, not that a site is trustworthy.
- The tool does not make network requests and cannot confirm current site reputation.
- Password feedback checks composition only, not reuse, uniqueness, or exposure in data breaches.

## Future improvements
Possible extensions include a GUI, configurable rules, report export, a curated threat-intelligence feed from a trusted provider, and unit tests. Any online integration should protect privacy and be used only with authorized data.


## Graphical user interface (GUI)
A desktop GUI built with Tkinter is included in `cybersecurity_gui.py`.

Run it from the project folder:
```bash
python cybersecurity_gui.py
```

The window has three tabs:
- **URL Inspector** — review basic offline URL warning signs.
- **Password Check** — get composition feedback for a test password.
- **Dataset Review** — review the included sample CSV or select another CSV.

Tkinter is commonly included with standard Python installations. If Python reports that Tkinter is unavailable, install a Python distribution that includes Tk support. The GUI does not visit URLs or send passwords to the internet.
