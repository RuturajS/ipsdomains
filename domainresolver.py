 #####                       #######                                  
#     #   ##   #    #       #       #    # #####  ###### #      #  ####  
#        #  #  ##  ##       #       #    # #    # #      #      # #    # 
#  #### #    # # ## # ##### #####   #    # #####  #####  #      # #      
#     # ###### #    #       #       #    # #    # #      #      # #  ### 
#     # #    # #    #       #       #    # #    # #      #      # #    # 
 #####  #    # #    #       #        ####  #####  ###### ###### #  ####  

# File crawls IP ranges defined in ips variable and extracts domain names from certificates
# It then checks each domain and logs the IP, Host, Status Code, and Headers delimited by "|"
Print("Auther : Ruturaj Sharbidre")

import requests
import urllib3
import time
import ssl
import OpenSSL
from socket import *
import argparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Default settings
throttle = 1  # seconds to delay requests for WAF
timeout = 1   # seconds before a request times out

# Set up argparse for command-line arguments
parser = argparse.ArgumentParser(description='Scan IP ranges for SSL certificates and domain info.')
parser.add_argument('-ips', type=str, required=True, help='Comma-separated list of IP prefixes (e.g., 127.0.0.1,45.25.25.1)')
args = parser.parse_args()

# Parse IP prefixes from the command line
ips = args.ips.split(',')

# Headers for the HTTP requests
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:100.0) Gecko/20100101 Firefox/100.0',
    'Accept': '*/*',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate, br'
}

# Initialize the output file
with open('domains.csv', 'w') as o:
    pass  # Just to clear the file initially

# Function to get Subject Alternative Names (SAN) from the certificate
def get_certificate_san(x509cert):
    san = ''
    ext_count = x509cert.get_extension_count()
    for i in range(ext_count):
        ext = x509cert.get_extension(i)
        if 'subjectAltName' in str(ext.get_short_name()):
            san = ext.__str__()
    return san

# Function to check the site and log the status
def check_site(ip, host):
    try:
        r = requests.get(url="https://" + host, verify=False, headers=headers, timeout=timeout)
        status_code = r.status_code
        headers_info = r.headers
        print(host, status_code)
        
        with open('domains.csv', 'a') as o:
            o.write(f"{ip}|{host}|{status_code}|{headers_info}\n")
    except requests.RequestException as e:
        print(f"Error with {host}: {e}")

# List to keep track of processed hosts
host_list = []

# Loop through each IP range prefix provided by the user
for prefix in ips:
    for i in range(1, 256):
        time.sleep(throttle)
        ip = f"{prefix}.{i}"
        print(f"Checking IP: {ip}")
        
        try:
            setdefaulttimeout(timeout)
            cert = ssl.get_server_certificate((ip, 443))
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
            
            # Process CN (common name) if not already in host_list
            cn = x509.get_subject().CN
            if f"{ip}|{cn}" not in host_list:
                host_list.append(f"{ip}|{cn}")
                check_site(ip, cn)
            
            # Process SAN (subject alternative names) if not already in host_list
            try:
                san_list = get_certificate_san(x509).split(',')
                for san in san_list:
                    alt_name = san.split('DNS:')[1]
                    if f"{ip}|{alt_name}" not in host_list:
                        host_list.append(f"{ip}|{alt_name}")
                        check_site(ip, alt_name)
            except Exception as e:
                print(f"Error processing SAN for {ip}: {e}")
        
        except Exception as e:
            print(f"Error fetching certificate for {ip}: {e}")
