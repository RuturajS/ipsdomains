 #####                       #######                                  
#     #   ##   #    #       #       #    # #####  ###### #      #  ####  
#        #  #  ##  ##       #       #    # #    # #      #      # #    # 
#  #### #    # # ## # ##### #####   #    # #####  #####  #      # #      
#     # ###### #    #       #       #    # #    # #      #      # #  ### 
#     # #    # #    #       #       #    # #    # #      #      # #    # 
 #####  #    # #    #       #        ####  #####  ###### ###### #  ####  

# File crawls IP ranges defined in ips variable and extracts domain names from certificates
# It then checks each domain and logs the IP, Host, Status Code, and Headers delimited by "|"

import requests, urllib3, time, ssl, OpenSSL
from socket import *
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

throttle = 1 #seconds to delay requests for WAF
timeowt = 1 #seconds before a request times out
ips = ['100.200.100.','200.100.200.','1.2.3.'] #example IP structure, scans 255 for each block

o = open('domains.csv', 'w')
o.close()

h = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:100.0) Gecko/20100101 Firefox/100.0',
'Accept': '*/*',
'Accept-Language': 'en-US,en;q=0.5',
'Accept-Encoding': 'gzip, deflate, br'}

def get_certificate_san(x509cert):
    san = ''
    ext_count = x509cert.get_extension_count()
    for i in range(0, ext_count):
        ext = x509cert.get_extension(i)
        if 'subjectAltName' in str(ext.get_short_name()):
            san = ext.__str__()
    return san

def checkSite(ip,host):
    r = requests.get(url="https://"+host, verify=False, headers=h, timeout=timeowt)
    sc = r.status_code
    print(host,sc)
    hh = r.headers
    o = open('domains.csv', 'a')
    o.write(str(ip)+"|"+str(host)+"|"+str(sc)+"|"+str(hh)+"\n")
    o.close()

hostList = []
# Loop entire IP ranges to grab certs and extract hostname and alt names
for prefix in ips:
    i = 0
    while i < 255:
        time.sleep(throttle)
        i = i +1
        ip = prefix+str(i)
        print(ip)
        try:
            setdefaulttimeout(timeowt)
            cert = ssl.get_server_certificate((ip, '443'))
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
            
            # Grab HOST name and append to list, but only if they aren't already there.
            try:
                if ip+"|"+x509.get_subject().CN not in hostList:
                    hostList.append(ip+"|"+x509.get_subject().CN) 
                    checkSite(ip,x509.get_subject().CN)
            except:
                pass 
                
            # Grab ALT Names and append to list, but only if they aren't already there.
            try:
                sanList = get_certificate_san(x509).split(',')
                for san in sanList:
                    if ip+"|"+san.split('DNS:')[1] not in hostList:
                        hostList.append(ip+"|"+san.split('DNS:')[1])
                        try:
                            checkSite(ip,san.split('DNS:')[1])
                        except:
                            pass
            except Exception as e:
                print(e)
                pass 
            
        except Exception as e:
            print(e)
            pass 


           
