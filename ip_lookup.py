import socket

def lookup_ip(ip_or_domain):
    try:
        ip_address = socket.gethostbyname(ip_or_domain)
        return {"IP Address": ip_address}
    except socket.gaierror:
        return {"Error": "Invalid domain or IP"}
