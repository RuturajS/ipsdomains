# Domains Resolver 
Hi all this is Script written by Z university guy i just made changes along to make it work really fast with on command line hope you like it !

>File crawls IP ranges defined in ips variable and extracts domain names from certificates # It then checks each domain and logs the IP, Host, Status Code, and Headers delimited by "|"


<b>Installation</b>

<code> git clone https://github.com/RuturajS/ipsdomains.git </code></br>
<code> cd ipsdomains </code></br>
<code> pip3 install -r requirements.txt </code></br>


To Ran a scan for IPS ranges use below command</br>

<code> python3 domainresolver.py -ips 127.0.0,192.168.1.1  </code></br>

it will search for Domains extracting it by crawling SSL certificate from Ips.
