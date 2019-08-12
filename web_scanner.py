import os
from urllib.parse import urlparse
import socket
import nmap
import urllib.request  as urllib2 
import re

FILE_COUNT=1
response = urllib2.urlopen("https://dotesports.com/rainbow-6/news/team-secret-look-dangerous-at-the-six-major-raleigh")

def create_dir(dir):
    """[this function creates a dir to saves the logs]
    
    Arguments:
        dir {[string]} -- [the path that we want to save the files]
    """
    if not os.path.exists(dir):
        os.makedirs(dir)

def write_file(data):
    global FILE_COUNT
    """[this function writes into the file ]
    
    Arguments:
        path {[string]} -- [the path of the file]
        data {[string]} -- [the data that we want to save]
    """
    path = r"D:\users\\Documents\\web_scanner\\file_content\\"
    file = open(path + str(FILE_COUNT)+ ".txt" , 'wb')
    #data = data.decode("utf-8", 'ignore') 
    file.write(data)
    file.close()
    FILE_COUNT = FILE_COUNT + 1

def get_domain(url):
    """[this function gets the domain name from the url]
    
    Arguments:
        url {[string]} -- [url]
    """
    domain = urlparse(url)
    return domain.netloc 

def get_ip(url):
    return socket.gethostbyname(get_domain(url))


def get_ports(url):    
    nmScan = nmap.PortScanner()
    
    # scan localhost for ports in range 21-443
    nmScan.scan('127.0.0.1', '21-443')
    
    # run a loop to print all the found result about the ports
    for host in nmScan.all_hosts():
            print('Host : %s (%s)' % (host, nmScan[host].hostname()))
            print('State : %s' % nmScan[host].state())
            for proto in nmScan[host].all_protocols():
                print(' --  --  --  --  -- ')
                print('Protocol : %s' % proto)
     
                lport = nmScan[host][proto].keys()
                lport.sort()
                for port in lport:
                    print ('port : %s\tstate : %s' % (port, nmScan[host][proto][port]['state']))

def get_sites_code(link):
    """[this function finds the source code of the given website]
    """
    try:
        res = urllib2.urlopen(link)
        write_file(res.read())
    except:
        print("couldnt open")
    
        
        
def get_links():
    global response
    page_source = response.read()
    links = re.findall('"((http|ftp)s?://.*?)"', page_source.decode("utf-8"))
    for link in links :
        if not "jpg" in link[0] and "dotesports.com" in link[0]:
            get_sites_code(link[0])
            print(link[0])



#get_ports("https://dotesports.com/rainbow-6/news/team-secret-look-dangerous-at-the-six-major-raleigh")
get_links()


