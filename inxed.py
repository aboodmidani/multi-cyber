import streamlit as st
from web_vulnerability_scanner import run_web_vulnerability_scan
from phishing_email_analyzer import analyze_email
from ip_lookup import lookup_ip
from malware_url_scanner import scan_url_for_malware
from email_breach_checker import check_email_breach
from whois_lookup import lookup_whois
from port_scanner import scan_ports

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
    "IP Lookup",
    "Malware URL Scanner",
    "Email Breach Checker",
    "WHOIS Lookup",
    "Port Scanner"
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

# Malware URL Scanner
elif page == "Malware URL Scanner":
    st.markdown("<div class='title'>🦠 Malware URL Scanner</div>", unsafe_allow_html=True)
    url = st.text_input("Enter URL to scan:")
    if st.button("🔍 Scan URL") and url:
        with st.spinner("Scanning for malware..."):
            result = scan_url_for_malware(url)
        st.success("✅ Scan Completed!")
        with st.expander("📋 Scan Results"):
            st.write(result)

# Email Breach Checker
elif page == "Email Breach Checker":
    st.markdown("<div class='title'>📧 Email Breach Checker</div>", unsafe_allow_html=True)
    email_input = st.text_input("Enter Email Address:")
    if st.button("🔍 Check Breach") and email_input:
        with st.spinner("Checking for breaches..."):
            breach_info = check_email_breach(email_input)
        st.success("✅ Breach Check Completed!")
        with st.expander("📋 View Breach Details"):
            st.write(breach_info)

# WHOIS Lookup
elif page == "WHOIS Lookup":
    st.markdown("<div class='title'>🌐 WHOIS Lookup</div>", unsafe_allow_html=True)
    domain = st.text_input("Enter Domain (e.g., example.com):")
    if st.button("🔍 Lookup") and domain:
        with st.spinner("Fetching WHOIS data..."):
            whois_info = lookup_whois(domain)
        st.success("✅ WHOIS Lookup Completed!")
        with st.expander("📋 WHOIS Data"):
            st.write(whois_info)

# Port Scanner
elif page == "Port Scanner":
    st.markdown("<div class='title'>🔌 Port Scanner</div>", unsafe_allow_html=True)
    target_host = st.text_input("Enter Target IP or Domain:")
    if st.button("🔎 Scan Ports") and target_host:
        with st.spinner("Scanning ports..."):
            port_results = scan_ports(target_host)
        st.success("✅ Port Scan Completed!")
        with st.expander("📋 Scan Results"):
            st.write(port_results)
