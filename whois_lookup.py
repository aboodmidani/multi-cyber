import streamlit as st
import whois as whois_lib  # Rename import to avoid conflicts

def lookup_whois(domain):
    try:
        domain_info = whois_lib.whois(domain)
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

# Streamlit UI
st.markdown("<div class='title'>🌐 WHOIS Lookup</div>", unsafe_allow_html=True)
domain = st.text_input("Enter Domain (e.g., example.com):")

if st.button("🔍 Lookup") and domain:
    with st.spinner("Fetching WHOIS data..."):
        whois_info = lookup_whois(domain)
    st.success("✅ WHOIS Lookup Completed!")
    with st.expander("📋 WHOIS Data"):
        st.write(whois_info)
