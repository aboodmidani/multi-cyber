import streamlit as st
import requests
import socket

def lookup_ip(ip_or_domain):
    """Fetch IP information including location, ISP, and server details."""
    try:
        # Convert domain to IP if necessary
        ip_address = socket.gethostbyname(ip_or_domain)
        
        # Use ipinfo.io API to fetch details
        response = requests.get(f"http://ipinfo.io/{ip_address}/json")
        data = response.json()
        
        return {
            "IP Address": data.get("ip", "N/A"),
            "Hostname": data.get("hostname", "N/A"),
            "City": data.get("city", "N/A"),
            "Region": data.get("region", "N/A"),
            "Country": data.get("country", "N/A"),
            "Location (Lat, Long)": data.get("loc", "N/A"),
            "ISP": data.get("org", "N/A"),
            "Timezone": data.get("timezone", "N/A"),
        }
    except Exception as e:
        return {"Error": str(e)}


