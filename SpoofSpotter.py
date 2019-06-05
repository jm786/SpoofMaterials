#!/usr/bin/env python2

from __future__ import print_function
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import logging.handlers
import socket
from scapy.all import *
import thread
import threading
import SocketServer
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import datetime
import random, string
import argparse
import sys
import subprocess
from array import array
import hpfeeds
import json

#################################################
# Spoof Sniffer                                 #
#   -A tool to catch spoofed NBNS responses     #
#     Spoofed responses are alerterd on with    #
#     email and/or SYSLOG                       #
#                                               #
# Written by Karl Fosaaen                       #
#     Twitter: @kfosaaen                        #
#################################################

# Some static variables
QUERY_NAME = (subprocess.check_output("hostname -d", shell=True).translate(None, string.punctuation)).upper()
SENT = 'false'
BADIPs = []

# Show all ipaddresses independent of name resolution
# then pick first from list (split by space)
hostnameI = subprocess.check_output("hostname -I", shell=True).rstrip().split(" ")[0]
hostnameB = subprocess.check_output(["ipcalc -b %s" % hostnameI.rstrip()+"/24"], shell=True).rstrip()[10:]
iface = subprocess.check_output("ip r | egrep '%s'" % hostnameI, shell=True).split(" ")[2]

# Parser Starter
parser = argparse.ArgumentParser(description='A tool to catch spoofed NBNS responses')

# Required Flags
parser.add_argument('-i', action="store", metavar='10.1.10.1', help='The IP of this host', required=False, const=hostnameI, nargs='?', default=hostnameI)
parser.add_argument('-b', action="store", metavar='10.1.10.255', help='The Broadcast IP of this host', required=False, const=hostnameB, nargs='?', default=hostnameB)
parser.add_argument('-g', action="store", metavar='(host,ident,secret,channel,port)', help="The registration for HPfeed", required=True, nargs='+')

# Optional Flags
parser.add_argument('-f','-F', action="store", metavar='/home/nbns.log', help='File name to save a log file')
parser.add_argument('-S', action="store", metavar='true', help='Log to local Syslog - this is pretty beta')
parser.add_argument('-e', action="store", metavar='you@example.com', help='The email to receive alerts at')
parser.add_argument('-s', action="store", metavar='192.168.1.109', help='Email Server to Send Emails to')
parser.add_argument('-n', action="store", metavar='EXAMPLEDOMAIN', help='The string to query with NBNS, this should be unique')
parser.add_argument('-R', action="store", metavar='5', help='The number of Garbage SMB Auth requests to send to the attacker')
parser.add_argument('-c', action="store", metavar='true', help='Continue Emailing After a Detection, could lead to spam')
parser.add_argument('-d', action="store", metavar='5', help='Time delay (in seconds) between NBNS broadcasts, reduces network noise')
parser.add_argument('--spam', action="store", metavar='true', help='Use SpoofSpotter to spam')
parser.add_argument('--honeyuser', action="store", metavar='15', help='Send known users for detection')
args = parser.parse_args()

# Handle Custom Queries
if args.n:
    QUERY_NAME = args.n

# Random String Generation
def randomword():
    length = random.randint(8,20)
    s = "abcdefghijklmnopqrstuvwxyz01234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()?"
    return "".join(random.sample(s,length))


# Scapy broadcast packet creation
pkt = IP(src=args.i,dst=args.b)/UDP(sport=137, dport='netbios_ns')/NBNSQueryRequest(SUFFIX="file server service",QUESTION_NAME=QUERY_NAME, QUESTION_TYPE='NB')

# What time is it?
now = datetime.datetime.now()

# Email function
def sendEmail(REMAIL, ESERVER, IP, MAC):
    me = 'spoofspotter@netspi.com'
    you = REMAIL
    server = ESERVER

    msg = MIMEMultipart('alternative')

    msg['Subject'] = 'A spoofed NBNS response was detected'
    msg['From'] = me
    msg['To'] = you

    now1 = datetime.datetime.now()
    BODY = 'A spoofed NBNS response for %s was detected by %s at %s from host %s - %s' %(QUERY_NAME, args.i, str(now1), IP, MAC)

    part1 = MIMEText(BODY, 'plain')

    msg.attach(part1)

    s = smtplib.SMTP(server)
    s.sendmail(me, [you], msg.as_string())
    s.quit()
    # Thanks Python Example Code

    # Flag for preventing email spamming
    if not args.c:
        global SENT
        SENT = 'true'
    print ("Email Sent")

#Sends out the queries
def sender():
    while 1:
        send (pkt, verbose=0)
        # If there's a delay set, then wait
        if args.d:
            time.sleep(float(args.d))
        else:
            time.sleep(float(1))

def random_username(user_type):
    folder = os.path.dirname(os.path.abspath(__file__))
    filepath = os.path.join(folder, 'last_names.txt')
    with open(filepath, 'r') as f:
        names = f.read().splitlines()
    l_name = random.choice(names)
    f_name = random.choice(list(string.ascii_lowercase))
    if (user_type == "honeyuser"):
        suffix = ["-sysadmin", "-itadmin", "-idevops", "-sysop"]
        name = f_name+l_name+random.choice(suffix)
    else:
        name = f_name+l_name

    return name

def auth_request(randpass, pathstr, ftpstr, wwwstr):
    subprocess.Popen(['smbclient', '-U', randpass, pathstr], stderr=subprocess.STDOUT, stdout=subprocess.PIPE).communicate()[0]
    subprocess.Popen(['wget', ftpstr, '-O', '/dev/null'], stderr=subprocess.STDOUT, stdout=subprocess.PIPE).communicate()[0]
    subprocess.Popen(['wget', wwwstr, '-O', '/dev/null'], stderr=subprocess.STDOUT, stdout=subprocess.PIPE).communicate()[0]

#Handler for incoming NBNS responses
def get_packet(pkt):
    if not pkt.getlayer(NBNSQueryRequest):
        return
    if pkt.FLAGS == 0x8500:
        now2 = datetime.datetime.now()
        print ('A spoofed NBNS response for %s was detected by %s at %s from host %s - %s' %(QUERY_NAME, args.i, str(now2), pkt.getlayer(IP).src, pkt.getlayer(Ether).src))
        logged = 0
        for i in BADIPs:
            if i == pkt.getlayer(IP).src:
                logged = 1
        if logged == 0:
            BADIPs.append(str(pkt.getlayer(IP).src))
            global SENT
            SENT = 'false'

        #if the file flag is set, then write the log
        if args.f:
            f = open(args.f, 'a')
            f.write('A spoofed NBNS response for %s was detected by %s at %s from host %s - %s\n' %(QUERY_NAME, args.i, str(now2), pkt.getlayer(IP).src, pkt.getlayer(Ether).src))
            f.close()
        #if email flags set, call the email function
        if args.e and args.s and SENT=='false':
            sendEmail(args.e, args.s, pkt.getlayer(IP).src, pkt.getlayer(Ether).src)
        #if syslog flag is set, then log it
        if args.S:
            NBNSLogger = logging.getLogger('NBNSLogger')
            NBNSLogger.setLevel(logging.DEBUG)
            #change your syslog stuff here - this is pretty beta, feel free to change this.
            handler = logging.handlers.SysLogHandler(address = ('localhost',514), facility=19)
            NBNSLogger.addHandler(handler)
            NBNSLogger.critical('A spoofed NBNS response for %s was detected by %s at %s from host %s - %s\n' %(QUERY_NAME, args.i, str(now2), pkt.getlayer(IP).src, pkt.getlayer(Ether).src))
            #Seriously, I didn't test this with an actual syslog server, please let me know if this works for you
                        #if the respond flag is set, respond with x number of hashes

        if args.spam:
            target_attacker_IP = pkt.getlayer(IP).src
            print ('Sending 1000 hashes to %s'%(target_attacker_IP))
            for x in range(5):
                #Sends SMB, FTP, and WWW Auth
                for x in range (200):
                    #Sends SMB, FTP, and WWW Auth
                    name = random_username("")
                    randpass = 'AMNHORG/%s%%%s'%(name, randomword())
                    pathstr = '//%s/C$'%(target_attacker_IP)
                    ftpstr = 'ftp://%s:%s@%s'%(name, randomword(), target_attacker_IP)
                    wwwstr = 'http://%s:%s@%s/test'%(name, randomword(), target_attacker_IP)

                    thread_name = "thread" + str(x)
                    thread_name = threading.Thread(target=auth_request,args=(randpass, pathstr, ftpstr, wwwstr))
                    thread_name.start()

        if args.R:
            global hpclient
            global dport
            target_attacker_IP = pkt.getlayer(IP).src
            try:
                if TCP in pkt:
                    dport=pkt[TCP].dport
                else:
                    dport=80
                hpclient.publish('spoofspotter.events', json.dumps({"src_ip": str(target_attacker_IP), "dst_ip": hostnameI , "dst_port": dport}))
            except Exception as e:
                print ('feed exception: %s' %e)

            print ('Sending %d hashes to %s'%(int(args.R), target_attacker_IP))
            for x in range(0, int(args.R)):
                #Sends SMB, FTP, and WWW Auth
                name = random_username("")
                randpass = 'AMNHORG/%s%%%s'%(name, randomword())
                pathstr = '//%s/C$'%(target_attacker_IP)
                ftpstr = 'ftp://%s:%s@%s'%(name, randomword(), target_attacker_IP)
                wwwstr = 'http://%s:%s@%s/test'%(name, randomword(), target_attacker_IP)

                print("Sending %s %s" % (pathstr, randpass))
                auth_request(randpass, pathstr, ftpstr, wwwstr)

        if args.honeyuser:
            target_attacker_IP = pkt.getlayer(IP).src
            print ('Sending %d hashes to %s'%(int(args.honeyuser), target_attacker_IP))
            for x in range(0, int(args.honeyuser)):
                #Sends SMB, FTP, and WWW Auth
                name = random_username("honeyuser")
                randpass = 'AMNHORG/%s%%%s'%(name, randomword())
                pathstr = '//%s/C$'%(target_attacker_IP)
                ftpstr = 'ftp://%s:%s@%s'%(name, randomword(), target_attacker_IP)
                wwwstr = 'http://%s:%s@%s/test'%(name, randomword(), target_attacker_IP)

                print("Sending %s %s" % (pathstr, randpass))
                auth_request(randpass, pathstr, ftpstr, wwwstr)
                time.sleep(1200.0)

def main():
    global hpclient
    try:
        hpclient = hpfeeds.new(args.g[0], 10000, args.g[1], args.g[2])

        if args.f:
            f = open(args.f, 'a')
            f.write('Starting Server at %s\n' %(str(now)))
            f.close()
        print ("Starting NBNS Request Thread...")
        thread.start_new(sender,())
        try:
            print ("Starting UDP Response Server...")
            sniff(iface=iface,filter="udp and port 137",store=0,prn=get_packet)
        except KeyboardInterrupt:
            print ("\nStopping Server and Exiting...\n")
            now3 = datetime.datetime.now()
            if args.f:
                f = open(args.f, 'a')
                f.write('Stopping Server at %s\n' %(str(now3)))
                f.close()
        except Exception as err:
           print ("Server could not be started, confirm you're running this as root.\n %s" % err)
    except KeyboardInterrupt:
        exit()
    except Exception as err:
        print ("Server could not be started, confirm you're running this as root.\n %s" % err)
    finally:
        hpclient.close()
main()
