import streamlit as st
import whois as whois_module

def lookup_whois(domain):
    try:
        domain_info = whois_module.whois(domain)
        return {
            "Domain Name": domain_info.domain_name,
            "Registrar": domain_info.registrar,
            "WHOIS Server": domain_info.whois_server,
            "Creation Date": domain_info.creation_date,
            "Expiration Date": domain_info.expiration_date,
            "Updated Date": domain_info.updated_date,
            "Name Servers": domain_info.name_servers,
            "Status": domain_info.status,
            "Emails": domain_info.emails
        }
    except Exception as e:
        return {"Error": str(e)}
