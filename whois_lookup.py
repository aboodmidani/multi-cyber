import streamlit as st
import whois

def perform_whois_lookup(domain):
    try:
        domain_info = whois.whois(domain)
        return domain_info
    except:
        return "Invalid domain or WHOIS lookup failed."

