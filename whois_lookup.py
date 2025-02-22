import streamlit as st
import whois as whois_module

def lookup_whois(domain):
    try:
        domain_info = whois_module.whois(domain)
        # Handle cases where domain_info might return a list or single value
        if isinstance(domain_info.domain_name, list):
            domain_name = domain_info.domain_name[0]
        else:
            domain_name = domain_info.domain_name

        if isinstance(domain_info.name_servers, list):
            name_servers = ", ".join(domain_info.name_servers)
        else:
            name_servers = domain_info.name_servers

        return {
            "Domain Name": domain_name,
            "Registrar": domain_info.registrar,
            "WHOIS Server": domain_info.whois_server,
            "Creation Date": domain_info.creation_date,
            "Expiration Date": domain_info.expiration_date,
            "Updated Date": domain_info.updated_date,
            "Name Servers": name_servers,
            "Status": domain_info.status,
            "Emails": domain_info.emails
        }
    except Exception as e:
        return {"Error": str(e)}
