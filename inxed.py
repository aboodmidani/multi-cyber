import streamlit as st
from web_vulnerability_scanner import run_web_vulnerability_scan
from phishing_email_analyzer import analyze_email
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
    .stSpinner {
        color: white;
    }
    .st-expander {
        border-radius: 10px;
        background-color: #1e1e1e;
        padding: 10px;
    }
    .title {
        text-align: center;
        font-size: 24px;
        font-weight: bold;
    }
    .icon {
        font-size: 30px;
        padding-right: 10px;
    }
    </style>
    """, unsafe_allow_html=True
)

# Sidebar navigation
st.sidebar.title("🔍 Cyber Security Toolkit")
page = st.sidebar.radio("Select a Tool:", [
    "Web Vulnerability Scanner",
    "Phishing Email Analyzer",
    "IP Lookup"
])

# Web Vulnerability Scanner
if page == "Web Vulnerability Scanner":
    st.markdown("<div class='title'>🛡️ Web Vulnerability Scanner</div>", unsafe_allow_html=True)
    target_url = st.text_input("Enter the target URL (e.g., http://example.com):")
    if st.button("🚀 Start Scan") and target_url:
        with st.spinner("Scanning for vulnerabilities..."):
            results = run_web_vulnerability_scan(target_url)
        st.success("✅ Scan Completed!")
        with st.expander("📋 View Scan Results"):
            st.write(results)

# Phishing Email Analyzer
elif page == "Phishing Email Analyzer":
    st.markdown("<div class='title'>📧 Phishing Email Analyzer</div>", unsafe_allow_html=True)
    uploaded_file = st.file_uploader("Upload an .eml file", type=["eml"])
    if uploaded_file and st.button("🔎 Analyze Email"):
        with open("temp_email.eml", "wb") as f:
            f.write(uploaded_file.getbuffer())
        with st.spinner("Analyzing email..."):
            result = analyze_email("temp_email.eml")
        st.success("✅ Analysis Completed!")
        with st.expander("📋 View Analysis Details"):
            st.write(result)

# IP Lookup
elif page == "IP Lookup":
    st.markdown("<div class='title'>🌍 IP Lookup Tool</div>", unsafe_allow_html=True)
    ip_or_domain = st.text_input("Enter an IP or Domain (e.g., www.example.com, example.com):")
    if st.button("📡 Lookup") and ip_or_domain:
        with st.spinner("Fetching IP details..."):
            ip_info = lookup_ip(ip_or_domain)
        st.success("✅ Lookup Completed!")
        with st.expander("📋 View IP Information"):
            st.write(ip_info)
