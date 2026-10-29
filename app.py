import re
from urllib.parse import urlparse

import pandas as pd
import streamlit as st

st.set_page_config(
    page_title="Phishing URL Detection",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Phishing URL Detection System")
st.write("Cybersecurity College Mini Project")
st.caption("Built using Python, Streamlit and Pandas")

st.warning(
    "Educational project only. A low risk score does not guarantee "
    "that a website is safe."
)

SUSPICIOUS_WORDS = [
    "login", "verify", "account", "password", "secure",
    "banking", "signin", "payment", "urgent", "suspend",
    "unlock", "claim", "prize", "free", "gift"
]

SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "cutt.ly",
    "is.gd", "ow.ly", "buff.ly"
]


def analyze_url(raw_url):
    raw_url = str(raw_url).strip()

    if not raw_url:
        return {
            "URL": raw_url,
            "Risk Score": 0,
            "Risk Level": "Invalid",
            "Findings": "Enter a URL"
        }

    url = raw_url
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url

    parsed = urlparse(url)
    domain = (parsed.hostname or "").lower()

    score = 0
    findings = []

    # Check domain format
    if not domain or "." not in domain:
        score += 25
        findings.append("Invalid-looking domain")

    # Check HTTP
    if parsed.scheme == "http":
        score += 10
        findings.append("Uses HTTP instead of HTTPS")

    # Check @ symbol
    if "@" in parsed.netloc:
        score += 20
        findings.append("Contains @ symbol")

    # Check URL length
    if len(url) > 100:
        score += 10
        findings.append("Unusually long URL")

    # Check subdomains
    if len(domain.split(".")) >= 5:
        score += 10
        findings.append("Too many subdomain levels")

    # Check numeric domain
    if re.search(r"\d{5,}", domain):
        score += 10
        findings.append("Long number sequence in domain")

    # Check suspicious domain encoding
    if "xn--" in domain:
        score += 15
        findings.append("Punycode domain detected")

    # Check URL shorteners
    if domain in SHORTENERS:
        score += 15
        findings.append("URL shortener detected")

    # Check suspicious keywords
    matched_words = [
        word for word in SUSPICIOUS_WORDS
        if word in url.lower()
    ]

    if matched_words:
        score += min(25, len(matched_words) * 5)
        findings.append(
            "Suspicious keywords: " + ", ".join(matched_words)
        )

    # Check unusual ports
    if parsed.port and parsed.port not in (80, 443):
        score += 10
        findings.append("Unusual port number")

    score = min(score, 100)

    if score >= 50:
        risk = "HIGH"
    elif score >= 25:
        risk = "MEDIUM"
    else:
        risk = "LOW SIGNAL"

    if not findings:
        findings.append("No listed suspicious patterns found")

    return {
        "URL": raw_url,
        "Risk Score": score,
        "Risk Level": risk,
        "Findings": "; ".join(findings)
    }


# Navigation
scanner, batch, about = st.tabs([
    "🔍 URL Scanner",
    "📁 Batch Scanner",
    "📚 About Project"
])

with scanner:
    st.subheader("Check a suspicious URL")

    user_url = st.text_input(
        "Enter URL",
        placeholder="example.com/login"
    )

    if st.button("Analyze URL", type="primary"):
        if user_url.strip():
            result = analyze_url(user_url)

            c1, c2, c3 = st.columns(3)

            c1.metric(
                "Risk Score",
                str(result["Risk Score"]) + "/100"
            )
            c2.metric("Risk Level", result["Risk Level"])
            c3.metric("URL Length", str(len(user_url)))

            if result["Risk Level"] == "HIGH":
                st.error("High-risk indicators detected!")
            elif result["Risk Level"] == "MEDIUM":
                st.warning("Some suspicious indicators detected.")
            else:
                st.info(
                    "Few listed indicators detected. "
                    "This does not prove the URL is safe."
                )

            st.subheader("Analysis Findings")
            st.write(result["Findings"])

        else:
            st.error("Please enter a URL.")

with batch:
    st.subheader("Analyze multiple URLs")

    uploaded_file = st.file_uploader(
        "Upload a CSV file containing a column named url",
        type=["csv"]
    )

    if uploaded_file is not None:
        try:
            data = pd.read_csv(uploaded_file)

            if "url" not in data.columns:
                st.error("CSV must contain a column named url.")
            else:
                results = pd.DataFrame([
                    analyze_url(url)
                    for url in data["url"].dropna()
                ])

                st.dataframe(
                    results,
                    use_container_width=True
                )

                st.download_button(
                    "Download Results CSV",
                    results.to_csv(index=False).encode("utf-8"),
                    file_name="phishing_analysis.csv",
                    mime="text/csv"
                )

        except Exception as error:
            st.error(f"Could not read CSV: {error}")

with about:
    st.subheader("Project Abstract")

    st.write("""
    Phishing is a cyberattack in which attackers use deceptive
    messages and websites to steal passwords, financial details
    and other sensitive information.

    This project analyzes selected URL characteristics and
    generates a rule-based risk score to help users identify
    suspicious links.
    """)

    st.subheader("Objectives")

    st.markdown("""
    1. Detect suspicious URL patterns.
    2. Calculate a risk score.
    3. Classify URLs by risk level.
    4. Explain the suspicious indicators.
    5. Analyze multiple URLs using CSV.
    6. Export results for reporting.
    """)

    st.subheader("Technologies Used")

    st.markdown("""
    - Python
    - Streamlit
    - Pandas
    - Regular Expressions
    - URL Parsing
    """)

    st.subheader("Limitations")

    st.write("""
    This is a rule-based educational prototype. It does not
    check live threat databases or inspect website content.
    It can miss malicious URLs or flag legitimate ones.
    """)

st.divider()
st.caption("Cybersecurity Mini Project | Python + Streamlit")
