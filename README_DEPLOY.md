# Cybersecurity Awareness Toolkit — Web Deployment

Student: Atul Gond

This folder adds a browser-based Flask interface for the existing educational URL heuristic checker, password-composition feedback, and CSV dataset review.

## Deploy on Render

1. Copy `app.py`, `requirements.txt`, `render.yaml`, `templates/`, and `static/` into the root of your GitHub repository (`awarness-tookit`). Keep your existing desktop Python files too.
2. Commit and push the added files to the `main` branch.
3. Open https://dashboard.render.com/ and sign in with GitHub.
4. Choose **New + → Blueprint** if available, then select the repository and follow the `render.yaml` configuration. Alternatively choose **New + → Web Service** and set:
   - Runtime: Python 3
   - Build command: `pip install -r requirements.txt`
   - Start command: `gunicorn app:app`
   - Branch: `main`
5. Start the deploy. After the build succeeds, open the `onrender.com` URL shown on the service dashboard.

## Local test (Python 3.9)

From this folder, run:

    python -m pip install -r requirements.txt
    python app.py

Then open http://127.0.0.1:5000 in your browser.

## Windows 8 note

You can edit files in VS Code on Windows 8 if your installed versions still support it. Browser compatibility depends on the browser version; current hosting happens on Render, not on your laptop. If `pip install` fails on Python 3.9, check that pip is working with `python -m pip --version`. Do not upgrade Python or system components blindly on an older laptop.

## Privacy and limitations

- This educational demo uses simple URL heuristics. It does not visit the URL, verify live reputation, or prove a website is safe or malicious.
- The password checker does not store the password in a database and the frontend clears the field after checking. Use only made-up test passwords; hosting providers may retain operational logs, so do not enter real credentials.
- CSV uploads are limited to 1 MB and 200 rows per request. Uploaded CSV contents are processed in memory and are not intentionally saved by the app.
- Render free services may sleep after inactivity and take a short time to wake up.
