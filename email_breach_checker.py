import streamlit as st
import requests

def check_email_breach(email):
    api_url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    headers = {"hibp-api-key": "YOUR_API_KEY"}
    response = requests.get(api_url, headers=headers)
    
    if response.status_code == 200:
        return response.json()
    elif response.status_code == 404:
        return "No breaches found."
    else:
        return "Error checking breaches."

