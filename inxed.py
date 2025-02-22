import streamlit as st
import requests
import socket
import dns.resolver
import re
import whois
import time
from bs4 import BeautifulSoup

st.set_page_config(page_title="Cyber Security Toolkit", layout="wide")
st.title("🛡️ Cyber Security Toolkit")
st.sidebar.title("🔍 Select a Tool")
option = st.sidebar.radio("Choose a Security Tool:", [
    "Web Vulnerability Scanner",
    "Subdomain Takeover Detector",
    "Phishing Email Analyzer",
    "Intrusion Detection System (IDS) Lite",
    "IP Lookup"
])

def check_sql_injection(url):
    payload = "' OR '1'='1"
    test_url = f"{url}?id={payload}"
    try:
        response = requests.get(test_url, timeout=5)
        if "error in your SQL syntax" in response.text.lower():
            return "🚨 SQL Injection vulnerability detected!"
        return "✅ No SQL Injection vulnerability found."
    except requests.exceptions.RequestException as e:
        return f"⚠️ Error: {e}"

def check_xss(url):
    payload = "<script>alert('XSS')</script>"
    test_url = f"{url}?q={payload}"
    try:
        response = requests.get(test_url, timeout=5)
        if payload in response.text:
            return "🚨 XSS vulnerability detected!"
        return "✅ No XSS vulnerability found."
    except requests.exceptions.RequestException as e:
        return f"⚠️ Error: {e}"

def check_security_headers(url):
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        missing_headers = [h for h in ["X-Frame-Options", "X-XSS-Protection", "Content-Security-Policy"] if h not in headers]
        if missing_headers:
            return f"⚠️ Missing security headers: {', '.join(missing_headers)}"
        return "✅ All essential security headers are present."
    except requests.exceptions.RequestException as e:
        return f"⚠️ Error: {e}"

def detect_subdomain_takeover(subdomain):
    try:
        answers = dns.resolver.resolve(subdomain, 'CNAME')
        for rdata in answers:
            cname = str(rdata.target)
            if any(x in cname for x in ["amazonaws.com", "github.io", "herokuapp.com"]):
                return "🚨 Potential Subdomain Takeover detected!"
        return "✅ No subdomain takeover risk found."
    except dns.resolver.NoAnswer:
        return "✅ No CNAME records found."
    except Exception as e:
        return f"⚠️ Error: {e}"

def analyze_email(email):
    pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    if not re.match(pattern, email):
        return "⚠️ Invalid email format."
    return "✅ Email format appears valid."

def intrusion_detection(logs):
    alerts = []
    if "unauthorized access" in logs.lower():
        alerts.append("🚨 Unauthorized access detected!")
    if "failed login" in logs.lower():
        alerts.append("⚠️ Multiple failed login attempts detected.")
    return alerts if alerts else ["✅ No suspicious activity found."]

def ip_lookup(ip):
    try:
        info = whois.whois(ip)
        return info
    except Exception as e:
        return f"⚠️ Error: {e}"

if option == "Web Vulnerability Scanner":
    st.header("🔍 Web Vulnerability Scanner")
    url = st.text_input("Enter a URL (e.g., http://example.com)")
    if st.button("Scan"): 
        st.write(check_sql_injection(url))
        st.write(check_xss(url))
        st.write(check_security_headers(url))

elif option == "Subdomain Takeover Detector":
    st.header("🔎 Subdomain Takeover Detector")
    subdomain = st.text_input("Enter a Subdomain (e.g., sub.example.com)")
    if st.button("Check"):
        st.write(detect_subdomain_takeover(subdomain))

elif option == "Phishing Email Analyzer":
    st.header("📧 Phishing Email Analyzer")
    email = st.text_input("Enter an Email Address")
    if st.button("Analyze"):
        st.write(analyze_email(email))

elif option == "Intrusion Detection System (IDS) Lite":
    st.header("🛡️ Intrusion Detection System (IDS) Lite")
    logs = st.text_area("Paste Server Logs")
    if st.button("Analyze Logs"):
        for alert in intrusion_detection(logs):
            st.write(alert)

elif option == "IP Lookup":
    st.header("🌍 IP Lookup")
    ip = st.text_input("Enter an IP Address")
    if st.button("Lookup"):
        st.write(ip_lookup(ip))
