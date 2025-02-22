import streamlit as st
from web_vulnerability_scanner import run_web_vulnerability_scan
from subdomain_takeover_detector import find_subdomains
from phishing_email_analyzer import analyze_phishing_email
from ids_lite import run_ids_scan
from ip_lookup import lookup_ip

# Set up page config
st.set_page_config(page_title="Cyber Security Tools", layout="wide", initial_sidebar_state="expanded")

# Apply dark mode styling
st.markdown(
    """
    <style>
    body {
        background-color: #121212;
        color: white;
    }
    .stButton>button {
        background-color: #1f77b4;
        color: white;
        border-radius: 8px;
    }
    </style>
    """, unsafe_allow_html=True
)

# Sidebar navigation
st.sidebar.title("🔍 Cyber Security Toolkit")
page = st.sidebar.radio("Select a Tool:", [
    "Web Vulnerability Scanner",
    "Subdomain Takeover Detector",
    "Phishing Email Analyzer",
    "Intrusion Detection System (IDS) Lite",
    "IP Lookup"
])

# Web Vulnerability Scanner
if page == "Web Vulnerability Scanner":
    st.title("🛡️ Web Vulnerability Scanner")
    target_url = st.text_input("Enter the target URL (e.g., http://example.com):")
    if st.button("🚀 Start Scan") and target_url:
        with st.spinner("Scanning..."):
            results = run_web_vulnerability_scan(target_url)
        st.success("✅ Scan Completed!")
        st.write(results)

# Subdomain Takeover Detector
elif page == "Subdomain Takeover Detector":
    st.title("🌐 Subdomain Takeover Detector")
    domain = st.text_input("Enter a website domain (e.g., google.com):")
    if st.button("🔍 Find Subdomains") and domain:
        with st.spinner("Searching for subdomains..."):
            subdomains = find_subdomains(domain)
        st.success("✅ Search Completed!")
        st.write(subdomains)

# Phishing Email Analyzer
elif page == "Phishing Email Analyzer":
    st.title("📧 Phishing Email Analyzer")
    uploaded_file = st.file_uploader("Upload an .eml file", type=["eml"])
    if uploaded_file and st.button("🔎 Analyze Email"):
        with st.spinner("Analyzing email..."):
            result = analyze_phishing_email(uploaded_file)
        st.success("✅ Analysis Completed!")
        st.write(result)

# Intrusion Detection System (IDS) Lite
elif page == "Intrusion Detection System (IDS) Lite":
    st.title("🛠️ Intrusion Detection System (IDS) Lite")
    if st.button("🕵️ Run IDS Scan"):
        with st.spinner("Running IDS scan..."):
            ids_results = run_ids_scan()
        st.success("✅ IDS Scan Completed!")
        st.write(ids_results)

# IP Lookup Tool
elif page == "IP Lookup":
    st.title("🌍 IP Lookup Tool")
    ip_or_domain = st.text_input("Enter an IP or Website URL:")
    if st.button("📡 Lookup") and ip_or_domain:
        with st.spinner("Fetching IP details..."):
            ip_info = lookup_ip(ip_or_domain)
        st.success("✅ Lookup Completed!")
        st.write(ip_info)
