"""
Cybersecurity Awareness Toolkit - GUI Frontend
Author: Atul Gond
Compatible with Python 3.9+ using Tkinter (usually included with Python).

Run:
    python cybersecurity_gui.py
"""

import csv
import re
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from pathlib import Path
from urllib.parse import urlparse

from cybersecurity_awareness_toolkit import assess_password, inspect_url, analyze_dataset

APP_TITLE = "CyberShield | Cybersecurity Awareness Toolkit"


class CybersecurityApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1000x720")
        self.minsize(820, 600)
        self.configure(bg="#0b1020")
        self._setup_style()
        self._build_ui()

    def _setup_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TFrame", background="#0b1020")
        style.configure("Card.TFrame", background="#141c31")
        style.configure("TLabel", background="#0b1020", foreground="#e7edf9", font=("Segoe UI", 10))
        style.configure("Title.TLabel", background="#0b1020", foreground="#f4f7ff", font=("Segoe UI", 23, "bold"))
        style.configure("Sub.TLabel", background="#0b1020", foreground="#9eabc6", font=("Segoe UI", 10))
        style.configure("CardTitle.TLabel", background="#141c31", foreground="#ffffff", font=("Segoe UI", 13, "bold"))
        style.configure("CardText.TLabel", background="#141c31", foreground="#b8c5df", font=("Segoe UI", 10))
        style.configure("TButton", font=("Segoe UI", 10, "bold"), padding=(12, 8))
        style.configure("Accent.TButton", background="#7c5cff", foreground="#ffffff")
        style.map("Accent.TButton", background=[("active", "#6b4ce6")])
        style.configure("TEntry", fieldbackground="#0f172a", foreground="#f8fafc", insertcolor="#ffffff")
        style.configure("TNotebook", background="#0b1020", borderwidth=0)
        style.configure("TNotebook.Tab", background="#1b2540", foreground="#dce5fa", padding=(16, 10), font=("Segoe UI", 10, "bold"))
        style.map("TNotebook.Tab", background=[("selected", "#7c5cff")], foreground=[("selected", "#ffffff")])

    def _build_ui(self):
        header = ttk.Frame(self, padding=(26, 22, 26, 12))
        header.pack(fill="x")
        ttk.Label(header, text="CYBERSHIELD", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            header,
            text="Cybersecurity Awareness Toolkit  •  Learn to spot warning signs",
            style="Sub.TLabel",
        ).pack(anchor="w", pady=(5, 0))

        statrow = ttk.Frame(self, padding=(26, 6, 26, 16))
        statrow.pack(fill="x")
        for title, desc in [
            ("PASSWORD CHECK", "Composition feedback"),
            ("URL INSPECTOR", "Offline heuristics"),
            ("PRIVACY FIRST", "No network requests"),
        ]:
            card = ttk.Frame(statrow, style="Card.TFrame", padding=14)
            card.pack(side="left", fill="x", expand=True, padx=(0, 10))
            ttk.Label(card, text=title, style="CardTitle.TLabel").pack(anchor="w")
            ttk.Label(card, text=desc, style="CardText.TLabel").pack(anchor="w", pady=(4, 0))

        self.tabs = ttk.Notebook(self)
        self.tabs.pack(fill="both", expand=True, padx=26, pady=(0, 12))
        self.url_tab = ttk.Frame(self.tabs, padding=20)
        self.password_tab = ttk.Frame(self.tabs, padding=20)
        self.dataset_tab = ttk.Frame(self.tabs, padding=20)
        self.tabs.add(self.url_tab, text="URL Inspector")
        self.tabs.add(self.password_tab, text="Password Check")
        self.tabs.add(self.dataset_tab, text="Dataset Review")
        self._build_url_tab()
        self._build_password_tab()
        self._build_dataset_tab()

        footer = ttk.Frame(self, padding=(26, 0, 26, 14))
        footer.pack(fill="x")
        ttk.Label(
            footer,
            text="Educational tool only • Results are heuristic and do not prove a site is safe or malicious.",
            style="Sub.TLabel",
        ).pack(anchor="w")

    def _build_url_tab(self):
        ttk.Label(self.url_tab, text="Inspect a URL", font=("Segoe UI", 18, "bold")).pack(anchor="w")
        ttk.Label(
            self.url_tab,
            text="Enter a URL to review basic warning signs. The app does not visit the website.",
            wraplength=850,
        ).pack(anchor="w", pady=(5, 14))
        row = ttk.Frame(self.url_tab)
        row.pack(fill="x")
        self.url_entry = ttk.Entry(row)
        self.url_entry.pack(side="left", fill="x", expand=True, ipady=7)
        self.url_entry.insert(0, "https://example.com")
        ttk.Button(row, text="Inspect URL", style="Accent.TButton", command=self.check_url).pack(side="left", padx=(10, 0))
        self.url_result = tk.Text(
            self.url_tab, height=15, wrap="word", bg="#0f172a", fg="#e7edf9",
            insertbackground="#ffffff", relief="flat", font=("Consolas", 10), padx=14, pady=12
        )
        self.url_result.pack(fill="both", expand=True, pady=(16, 0))
        self.url_result.insert("1.0", "Your URL assessment will appear here.")
        self.url_result.configure(state="disabled")

    def check_url(self):
        result = inspect_url(self.url_entry.get())
        lines = [f"ASSESSMENT: {result['risk']}", "", f"URL: {result['url']}", "", "OBSERVATIONS"]
        lines += [f"  • {flag}" for flag in result["flags"]]
        lines += ["", "Safety reminder: HTTPS alone does not prove a website is trustworthy."]
        self._set_text(self.url_result, "\n".join(lines))

    def _build_password_tab(self):
        ttk.Label(self.password_tab, text="Password composition", font=("Segoe UI", 18, "bold")).pack(anchor="w")
        ttk.Label(
            self.password_tab,
            text="Use a test password only. Input stays in this app and is not saved or transmitted.",
            wraplength=850,
        ).pack(anchor="w", pady=(5, 14))
        row = ttk.Frame(self.password_tab)
        row.pack(fill="x")
        self.password_entry = ttk.Entry(row, show="•")
        self.password_entry.pack(side="left", fill="x", expand=True, ipady=7)
        ttk.Button(row, text="Check strength", style="Accent.TButton", command=self.check_password).pack(side="left", padx=(10, 0))
        self.show_password = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            self.password_tab, text="Show password while typing", variable=self.show_password,
            command=self.toggle_password
        ).pack(anchor="w", pady=(10, 0))
        self.password_result = tk.Text(
            self.password_tab, height=13, wrap="word", bg="#0f172a", fg="#e7edf9",
            insertbackground="#ffffff", relief="flat", font=("Consolas", 10), padx=14, pady=12
        )
        self.password_result.pack(fill="both", expand=True, pady=(16, 0))
        self.password_result.insert("1.0", "Strength feedback will appear here.")
        self.password_result.configure(state="disabled")

    def toggle_password(self):
        self.password_entry.configure(show="" if self.show_password.get() else "•")

    def check_password(self):
        password = self.password_entry.get()
        if not password:
            messagebox.showinfo("Password needed", "Enter a test password first.")
            return
        label, feedback = assess_password(password)
        lines = [f"COMPOSITION ASSESSMENT: {label}", "", "SUGGESTIONS"]
        lines += [f"  • {item}" for item in feedback]
        lines += ["", "This does not check password reuse or data-breach exposure."]
        self._set_text(self.password_result, "\n".join(lines))
        # Avoid retaining the entered password in the input after assessment.
        self.password_entry.delete(0, tk.END)

    def _build_dataset_tab(self):
        ttk.Label(self.dataset_tab, text="Sample dataset review", font=("Segoe UI", 18, "bold")).pack(anchor="w")
        ttk.Label(
            self.dataset_tab,
            text="Load the included sample_urls.csv or select another CSV with a URL column.",
            wraplength=850,
        ).pack(anchor="w", pady=(5, 14))
        row = ttk.Frame(self.dataset_tab)
        row.pack(fill="x")
        ttk.Button(row, text="Review included sample", style="Accent.TButton", command=self.review_sample).pack(side="left")
        ttk.Button(row, text="Choose CSV…", command=self.choose_csv).pack(side="left", padx=(10, 0))
        self.dataset_result = tk.Text(
            self.dataset_tab, height=18, wrap="word", bg="#0f172a", fg="#e7edf9",
            insertbackground="#ffffff", relief="flat", font=("Consolas", 9), padx=14, pady=12
        )
        self.dataset_result.pack(fill="both", expand=True, pady=(16, 0))
        self.dataset_result.insert("1.0", "Dataset review results will appear here.")
        self.dataset_result.configure(state="disabled")

    def review_sample(self):
        path = Path(__file__).with_name("sample_urls.csv")
        self.review_dataset(path)

    def choose_csv(self):
        filename = filedialog.askopenfilename(
            title="Select URL CSV", filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        if filename:
            self.review_dataset(Path(filename))

    def review_dataset(self, path):
        try:
            results = analyze_dataset(path)
        except (OSError, ValueError) as exc:
            messagebox.showerror("Could not read dataset", str(exc))
            return
        lines = [f"FILE: {path}", f"RECORDS REVIEWED: {len(results)}", "=" * 68]
        for i, result in enumerate(results, start=1):
            lines += [
                f"{i}. {result.get('example_label', 'Unlabelled')}",
                f"   URL: {result['url']}",
                f"   Assessment: {result['risk']}",
            ]
            lines += [f"   - {flag}" for flag in result["flags"]]
            lines.append("")
        self._set_text(self.dataset_result, "\n".join(lines))

    @staticmethod
    def _set_text(widget, content):
        widget.configure(state="normal")
        widget.delete("1.0", tk.END)
        widget.insert("1.0", content)
        widget.configure(state="disabled")


if __name__ == "__main__":
    app = CybersecurityApp()
    app.mainloop()
