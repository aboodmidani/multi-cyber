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

# Streamlit UI
st.title("📧 Email Breach Checker")
email = st.text_input("Enter your email:")
if st.button("🔍 Check Breach") and email:
    with st.spinner("Checking for breaches..."):
        result = check_email_breach(email)
    st.success("✅ Check Completed!")
    st.write("Breach Details:", result)
