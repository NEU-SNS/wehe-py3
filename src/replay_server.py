'''
#######################################################################################################
#######################################################################################################

Copyright 2018 Northeastern University

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
    
Goal: server replay script

Usage:
    python replay_server.py --ConfigFile=configs_local.cfg 

Mandatory arguments:
    pcap_folder: This is the folder containing parsed files necessary for the replay

Optional arguments:
    original_ports: if true, uses same server ports as seen in the original pcap
                      default: False

Example:
    sudo python replay_server.py --VPNint=tun0 --NoVPNint=eth0 --pcap_folder=[] --resultsFolder=[]

To kill the server:  
    ps aux | grep "python udp_server.py" |  awk '{ print $2}' | xargs kill -9
#######################################################################################################
#######################################################################################################
'''

import gevent.monkey
import tracemalloc
import linecache
import gc

gevent.monkey.patch_all()
from multiprocessing_logging import install_mp_handler
import pickle, atexit, re, urllib.request, urllib.error, urllib.parse, base64, reverse_geocode, hashlib
from python_lib import *
from datetime import datetime
from timezonefinder import TimezoneFinder
from dateutil import tz
import subprocess
import gevent, gevent.pool, gevent.server, gevent.queue, gevent.select, gevent.ssl
from gevent.lock import RLock
import netaddr as neta
import signal
from contextlib import contextmanager
from threading import Timer
from prometheus_client import start_http_server, Summary, Counter, Gauge

import weheResultsWriter as bqResultWriter
from third_party.uuid.uuid import UUID

DEBUG = 5

logger = logging.getLogger('replay_server')

# Prometheus metrics
REPLAY_COUNT = Counter("replay_count_total", "Total Number of Individual Replays", ['name'])
REPLAY_ERROR_COUNT = Counter("replay_erros_total", "Total Number of Errors on the Sidechannel", ['type'])
ATTEMPTED_REPLAY_COUNT = Counter("attemped_replay_count_total", "Total Number of Connections made to the Sidechannel")
CERT_EXPIRATION_DAYS = Gauge('days_until_cert_expiration', 'Days until the self-signed certificate expires')
DISK_USAGE = Gauge('disk_usage', '% of disk used')


@contextmanager
def timeout(time):
    # Register a function to raise a TimeoutError on the signal.
    signal.signal(signal.SIGALRM, raise_timeout)
    # Schedule the signal to be sent after ``time``.
    signal.alarm(time)

    try:
        yield
    except Exception("Timeout"):
        pass
    finally:
        # Unregister the signal so it won't be triggered
        # if the timeout is not reached.
        signal.signal(signal.SIGALRM, signal.SIG_IGN)


def display_top(snapshot, key_type='lineno', limit=10):
    snapshot = snapshot.filter_traces((
        tracemalloc.Filter(False, "<frozen importlib._bootstrap>"),
        tracemalloc.Filter(False, "<unknown>"),
    ))
    top_stats = snapshot.statistics(key_type)

    print("Top %s lines" % limit)
    for index, stat in enumerate(top_stats[:limit], 1):
        frame = stat.traceback[0]
        print("#%s: %s:%s: %.1f KiB"
              % (index, frame.filename, frame.lineno, stat.size / 1024))
        line = linecache.getline(frame.filename, frame.lineno).strip()
        if line:
            print('    %s' % line)

    other = top_stats[limit:]
    if other:
        size = sum(stat.size for stat in other)
        print("%s other: %.1f KiB" % (len(other), size / 1024))
    total = sum(stat.size for stat in top_stats)
    print("Total allocated size: %.1f KiB" % (total / 1024))


def raise_timeout(signum, frame):
    raise Exception("Timeout")


def get_size(obj, seen=None):
    """Recursively finds size of objects"""
    size = sys.getsizeof(obj)
    if seen is None:
        seen = set()
    obj_id = id(obj)
    if obj_id in seen:
        return 0
    # Important mark as seen *before* entering recursion to gracefully handle
    # self-referential objects
    seen.add(obj_id)
    if isinstance(obj, dict):
        size += sum([get_size(v, seen) for v in obj.values()])
        size += sum([get_size(k, seen) for k in obj.keys()])
    elif hasattr(obj, '__dict__'):
        size += get_size(obj.__dict__, seen)
    elif hasattr(obj, '__iter__') and not isinstance(obj, (str, bytes, bytearray)):
        size += sum([get_size(i, seen) for i in obj])
    return size


class TestObject(object):
    def __init__(self, ip, realID, replayName, testID):
        self.ip = ip
        self.replayName = replayName
        self.realID = realID
        self.testID = testID
        self.lastActive = time.time()
        self.allowedGap = 5 * 60

    def update(self, testID):
        LOG_ACTION(logger, 'UPDATING: {}, {}, {}'.format(self.realID, self.ip, self.replayName), indent=2, action=False)
        self.testID = testID
        self.lastActive = time.time()

    def isAlive(self):
        if time.time() - self.lastActive < self.allowedGap:
            return True
        else:
            return False

    def __rep__(self):
        return '{}--{}--{}--{}'.format(self.ip, self.realID, self.replayName, self.testID)


class ClientObj(object):
    '''
    A simple object to store client's info
    '''

    def __init__(self, incomingTime, realID, id, ip, replayName, testID, historyCount, extraString, connection,
                 clientVersion,
                 smpacNum, saction, sspec):
        self.id = id
        self.replayName = replayName
        self.connection = connection
        self.ip = id
        self.realID = realID
        self.testID = testID
        self.incomingTime = incomingTime
        self.extraString = extraString
        self.historyCount = historyCount
        self.clientVersion = clientVersion
        self.startTime = time.time()
        self.ports = set()
        self.hosts = set()
        self.exceptions = 'NoExp'
        self.success = False  # it turns to True if replay finishes successfully
        self.secondarySuccess = False  # it turns to True if results and jitter info finish successfully
        self.iperfRate = None
        self.mobileStats = None
        self.clientTime = None
        self.dumpName = None
        self.targetFolder = Configs().get('tmpResultsFolder') + '/' + realID + '/'
        self.tcpdumpsFolder = self.targetFolder + 'tcpdumpsResults/'
        self.clientXputFolder = self.targetFolder + 'clientXputs/'
        self.replayInfoFolder = self.targetFolder + 'replayInfo/'
        self.smpacNum = smpacNum
        self.saction = saction
        self.sspec = sspec
        self.uuid = None

        if not os.path.exists(self.targetFolder):
            os.makedirs(self.targetFolder)
            os.makedirs(self.tcpdumpsFolder)
            os.makedirs(self.clientXputFolder)
            os.makedirs(self.replayInfoFolder)

            decisionsFolder = self.targetFolder + 'decisions/'
            os.makedirs(decisionsFolder)

    def setDump(self, dumpName):
        self.dumpName = dumpName
        if Configs().get('tcpdumpInt') == "default":
            self.dump = tcpdump(dump_name=dumpName, targetFolder=self.tcpdumpsFolder)
        else:
            self.dump = tcpdump(dump_name=dumpName, targetFolder=self.tcpdumpsFolder,
                                interface=Configs().get('tcpdumpInt'))

    def create_info_json(self, infoFile):
        # To protect user privacy
        # anonymize client by modifying the ip to only first three octets, e.g., v4: 1.2.3.4 -> 1.2.3.0,
        # v6 : 1:2:3:4:5:6 -> 1:2:3:4:5:0000
        anonymizedIP = get_anonymizedIP(self.id)
        # The 16th element is used to indicate whether the user has alerted ARCEP, False by default,
        # changed to true by the analyzer when the client alerts
        # The 17th element is the client app verison
        with open(infoFile, 'w') as writeFile:
            json.dump([self.incomingTime, self.realID, anonymizedIP, anonymizedIP, self.replayName, self.extraString,
                          self.historyCount, self.testID,
                          self.exceptions, self.success, self.secondarySuccess, self.iperfRate,
                          time.time() - self.startTime, self.clientTime, self.mobileStats, False, self.clientVersion, self.uuid], writeFile)

    def get_info(self):
        return list(map(str, [self.incomingTime, self.realID, self.id, self.ip, self.replayName, self.extraString,
                              self.historyCount, self.testID, self.exceptions, self.success, self.secondarySuccess,
                              self.iperfRate, time.time() - self.startTime, self.clientTime, self.mobileStats]))


class TCPServer(object):
    def __init__(self, instance, Qs, greenlets_q, ports_q, errorlog_q, LUT, getLUT, sideChannel_all_clients,
                 buff_size=4096, pool_size=10000, hashSampleSize=400, timing=True):
        self.instance = instance
        self.Qs = Qs
        self.greenlets_q = greenlets_q
        self.ports_q = ports_q
        self.errorlog_q = errorlog_q
        self.LUT = LUT
        self.getLUT = getLUT
        self.buff_size = buff_size
        self.pool_size = pool_size
        self.hashSampleSize = hashSampleSize
        self.all_clients = sideChannel_all_clients
        self.timing = timing

    def run(self):
        '''
        Simply creates and runs a server with a pool if handlers.
        Note if original_ports is False, instance port is zero, so the OS picks a random free port
        '''
        pool = gevent.pool.Pool(self.pool_size)
        server = gevent.server.StreamServer(self.instance, self.handle, spawn=pool)
        server.init_socket()
        # This option is important to make sure packets are not merged.
        # This can happen in NOVPN tests where MTU is bigger than packets
        # (because record happened over VPN)
        server.socket.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
        server.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        server.start()
        self.instance = (self.instance[0], server.address[1])

    def handleCertRequest(self, connection):
        r = random.randint(2, 200)
        name = "replayCertPass_" + str(r)

        fname = "/opt/meddle/ClientCerts/%s.p12" % name
        data = dict()
        data["alias"] = name

        with open(fname, "rb") as image_file:
            encoded_string = base64.b64encode(image_file.read())

        data["cert"] = encoded_string
        data["pass"] = "1234"

        print(fname)
        response = 'HTTP/1.1 200 OK\r\n\r\n' + json.dumps(data)
        connection.sendall(response.encode())

    def handle(self, connection, address):
        '''
        Handles an incoming connection.
        
        Steps:
            0- Determine csp from hash LUT
                -if a sideChannel with the same id exists:
                    -if hash in LUT, done
                    -elif it's a GET request, consult getLUT (find closest get request)
                    -else, error!
                -else:
                    -if not a GET request, error
                    -elif "X-rr" exists, done.
                    -else, error!
            1- Put the handle greenlet on greenlets_q
            2- Reports the id and address on ports_q
            3- For every response set in Qs[replayName][csp]:
                a- receive expected request based on length (while loop)
                b- update buffer_len
                c- send response (for loop)
            4- Close connection
            
        IMPORTANT: if recv() returns an empty string --> the other side of the 
                   connection (client) is gone! and we just terminate the function 
                   (by calling return)
        '''
        clientIP = address[0]
        clientPort = str(address[1]).zfill(5)
        '''
        NEED TO REVISIT!!!!!!!!!
        
        For some reason, sometimes the clientIP looks weird and does not comply with either IPv4 nor IPv6 format! e.g. ::ffff:137.194.165.192
        This will break pcap cleaning. The below if is to fix this. It MUST be done in SideChannel.handle, TCPServer.handle, and UDPServer.handle
        '''
        if ('.' in clientIP) and (':' in clientIP):
            clientIP = clientIP.rpartition(':')[2]

        # This is because we identify users by IP (for now)
        # So no two users behind the same NAT can run at the same time
        id = clientIP

        # 0- Determine csp from hash Lookup-Table (See above for details)
        new_data = connection.recv(self.buff_size)
        new_data_string = new_data.decode('ascii', 'ignore')
        # theHash = hashlib.sha1(toHash.encode('ascii', 'ignore')).hexdigest()
        new_data_4hash = new_data_string[:self.hashSampleSize].encode('ascii', 'ignore')

        if (new_data_string.startswith('GET /WHATSMYIPMAN')) or (new_data_string == 'WHATSMYIPMAN?'):
            connection.sendall("HTTP/1.1 200 OK\r\n\r\n{}".format(clientIP).encode())
            return

        if new_data_string[0:3] == 'GET':
            itsGET = True
        else:
            itsGET = False

        if id in self.all_clients:
            idExists = True
        else:
            idExists = False

        # This is for random replays where we add the info to the beginning of the first packet
        if new_data_string.strip().startswith('X-rr;'):
            info = new_data_string.partition(';X-rr')[0]
            [id, replayCode, csp] = info.strip().split(';')[1:4]
            replayName = name2code(replayCode, 'code')
            exceptionsReport = ''

        # If we know who the client is:
        elif idExists:
            try:
                # (replayName, csp) = self.LUT['tcp'][hash(new_data_4hash)]
                # all_clients[id]'s only key is the replayName for this client
                replayName = list(self.all_clients[id].keys())[0]

                pickle_file = self.Qs[replayName]
                with open(pickle_file, 'br') as server_pickle:
                    Q, _, _, _, _, _ = pickle.load(server_pickle)

                # Since only one connection for each replay, the first (only) csp in the Q is the one
                csp = list(Q["tcp"].keys())[0]
                exceptionsReport = ''
            # The following exception handler is for checking header manipulations
            except KeyError:
                self.errorlog_q.put(
                    (get_anonymizedIP(id), 'Unknown packet from existing client', 'TCP', str(self.instance)))
                exceptionsReport = 'Unknown packet from existing client'

            if hashlib.sha1(new_data_4hash).hexdigest() not in self.LUT['tcp']:
                exceptionsReport = 'ContentModification'

        # If we DON'T know who the client is: (possibly because of IP flipping)
        else:
            # This part is for adding info as a X- header for cases where an HTTP proxy
            # with different IP (from sideChannel) exists.
            if itsGET:
                theDict = dict(re.findall(r"(?P<name>.*?): (?P<value>.*?)\r\n", new_data_string.partition('\n')[2]))
                theDict['GET'] = new_data_string.partition('\r\n')[0]

                try:
                    [id, replayCode, csp] = theDict['X-rr'].strip().split(';')
                    replayName = name2code(replayCode, 'code')

                    exceptionsReport = 'ipFlip-resolved'
                except KeyError:
                    connection.sendall('SuspiciousClientIP!;{}'.format(clientIP).encode())
                    return
            else:
                connection.sendall('SuspiciousClientIP!,{}'.format(clientIP).encode())
                self.errorlog_q.put(
                    (get_anonymizedIP(id), 'Unknown packet from unknown client', 'TCP', str(self.instance)))
                exceptionsReport = 'Unknown packet from unknown client'
                return

        try:
            dClient = self.all_clients[id][replayName]
            if exceptionsReport != '':
                dClient.exceptions = exceptionsReport
                # We can continue replay when contentModification happens (this happens when doing DPI reverse-engineering)
                if 'ContentModification' != exceptionsReport:
                    return
        except KeyError:
            self.errorlog_q.put((get_anonymizedIP(id), 'Unknown client', 'TCP', str(self.instance)))
            return

        # 1- Put the handle greenlet on greenlets_q
        self.greenlets_q.put((gevent.getcurrent(), id, replayName, 'tcp', str(self.instance)))

        # 2- Reports the id and address (both HOST and PORT) on ports_q
        self.ports_q.put(('host', id, replayName, clientIP))
        self.ports_q.put(('port', id, replayName, clientPort))

        # 3- Handle request and response
        # if an X-rr header was added, do not consider it as expected bytes
        XrrHeader = new_data_string.partition('\r\nX-rr')[2].partition('\r\n')[0]
        if len(XrrHeader) > 0:
            extraBytes = len(XrrHeader) + 6  # 6 is for '\r\nX-rr'
        else:
            extraBytes = 0

        buffer_len = len(new_data) - extraBytes

        # Make Server side changes on the fly, based on all_clients[id].values().[0], the clientObj
        clientO = list(self.all_clients[id].values())[0]
        # Get the packet number, and make changes on that packet
        smpacNum = clientO.smpacNum
        saction = clientO.saction
        sspec = clientO.sspec

        pCount = 1

        for response_set in Q["tcp"][csp]:
            if itsGET is True:
                '''
                 Some ISPs add/remove/modify headers (e.g. Verizon adding perma-cookies).
                 This may result in the size of the GET request be different than what it's supposed
                 to be. To insure this will not break things, for GET request we read everything
                 that's in the buffer (instead of just reading the number of bytes that are expected)
                 And in case the GET request is spilling over multiple packets (really shouldn't be 
                 more than 2 !!!), we do a select and read remaining data in the buffer.
                 '''
                if buffer_len == 0:
                    new_data = connection.recv(self.buff_size)
                    buffer_len += len(new_data)
                if buffer_len < response_set.request_len:
                    r, w, e = gevent.select.select([connection], [], [], timeout=0.01)
                    if r:
                        new_data = connection.recv(self.buff_size)
                        buffer_len += len(new_data)
            else:
                while buffer_len < response_set.request_len:
                    try:
                        new_data = connection.recv(min(self.buff_size, response_set.request_len - buffer_len))
                    except:
                        return False

                    if not new_data:
                        return False

                    buffer_len += len(new_data)

            # Once the request is fully received, send the response

            time_origin = time.time()

            for response in response_set.response_list:
                if pCount == smpacNum:
                    response.payload = sModify(str(response.payload), saction, sspec)

                if (self.timing is True) and ("port" not in replayName):
                    gevent.sleep(seconds=((time_origin + response.timestamp) - time.time()))
                try:
                    # response.payload.replace('video', 'walio')
                    connection.sendall(bytes.fromhex(response.payload))
                except Exception as e:
                    print("Error when sending data", e)
                    return False
                pCount += 1

            buffer_len = 0

        # 4- Close connection
        connection.shutdown(gevent.socket.SHUT_RDWR)
        connection.close()

        gc.collect()


class UDPServer(object):
    '''
    self.mapping: this is the client mapping that server keeps to keep track what portion of the trace is
                  being replayed by each client IP and Port. These mappings are passed to SideChannel which
                  cleans them whenever client disconnects
    '''

    def __init__(self, instance, Qs, notify_q, greenlets_q, ports_q, errorlog_q, LUT, sideChannel_all_clients,
                 buff_size=4096, pool_size=10000, timing=True):
        self.instance = instance
        self.Qs = Qs
        self.notify_q = notify_q
        self.greenlets_q = greenlets_q
        self.ports_q = ports_q
        self.errorlog_q = errorlog_q
        self.LUT = LUT
        self.all_clients = sideChannel_all_clients
        self.buff_size = buff_size
        self.pool_size = pool_size
        self.original_port = self.instance[1]
        self.mapping = {}  # self.mapping[id][clientPort] = (id, serverPort, replayName)
        self.send_lock = RLock()
        self.timing = timing

    def run(self):

        pool = gevent.pool.Pool(self.pool_size)

        self.server = gevent.server.DatagramServer(self.instance, self.handle, spawn=pool)
        self.server.start()

        self.instance = (self.instance[0], self.server.address[1])

    def handle(self, data, client_address):
        '''
        Data is received from client_address:
            -if self.mapping[id][clientPort] exists --> client has already been identified:
                -if serverPort is None --> server has already started sending to this client, no need
                 for any action
                -else, set self.mapping[id][clientPort] = (None, None, None) and start sending
                 to client
            -else, the client is identifying, so react.
        '''
        clientIP = client_address[0]
        clientPort = str(client_address[1]).zfill(5)

        '''
        NEED TO REVISIT!!!!!!!!!
        
        For some reason, sometimes the clientIP looks weird and does not comply with either IPv4 nor IPv6 format! e.g. ::ffff:137.194.165.192
        
        This will break pcap cleaning. The below if is to fix this. It MUST be done in SideChannel.handle, TCPServer.handle, and UDPServer.handle
        '''
        if ('.' in clientIP) and (':' in clientIP):
            clientIP = clientIP.rpartition(':')[2]

        # This is because we identify users by IP (for now)
        # So no two users behind the same NAT can run at the same time
        id = clientIP

        try:
            self.mapping[id][clientPort]
        except KeyError:
            try:
                if id in self.all_clients:
                    idExists = True
                    replayName = list(self.all_clients[id].keys())[0]

                    pickle_file = self.Qs[replayName]
                    with open(pickle_file, "br") as server_pickle:
                        Q, _, _, _, _, _ = pickle.load(server_pickle)

                    if not Configs().get('original_ips'):
                        packets, _ = merge_servers(Q['udp'])
                else:
                    idExists = False

                if not idExists:
                    self.errorlog_q.put((get_anonymizedIP(id), 'Unknown packet', 'UDP', str(self.instance)))
                    return

                else:
                    original_serverPort = list(packets.keys())[0]
                    original_clientPort = list(packets[original_serverPort].keys())[0]
            except:
                self.errorlog_q.put((get_anonymizedIP(id), 'Unknown packet', 'UDP', str(self.instance)))
                return

            if id not in self.mapping:
                self.mapping[id] = {}
            self.mapping[id][clientPort] = 1
            self.ports_q.put(('port', id, replayName, clientPort))

            gevent.Greenlet.spawn(self.send_Q, packets[original_serverPort][original_clientPort],
                                  time.time(), client_address, id, replayName)

    def send_Q(self, Q, time_origin, client_address, id, replayName):
        '''
        Sends a queue of UDP packets to client socket
        '''
        udp_test_timeout = 45
        # 1-Register greenlet
        self.greenlets_q.put((gevent.getcurrent(), id, replayName, 'udp', str(self.instance)))
        clientPort = str(client_address[1]).zfill(5)

        # 2-Let client know the start of new send_Q
        self.notify_q.put((id, replayName, clientPort, 'STARTED'))

        # 3- Start sending
        for udp_set in Q:
            if self.timing is True:
                gevent.sleep((time_origin + udp_set.timestamp) - time.time())

            with self.send_lock:
                self.server.socket.sendto(bytes.fromhex(udp_set.payload), client_address)

            time_progress = time.time() - time_origin
            if time_progress > udp_test_timeout:
                break

            if DEBUG == 2: print('\tsent:', udp_set.payload, 'to', client_address)
            if DEBUG == 3: print('\tsent:', len(udp_set.payload), 'to', client_address)

        # 4-Let client know the end of send_Q
        self.notify_q.put((id, replayName, clientPort, 'DONE'))

        gc.collect()


class SideChannel(object):
    '''
    Responsible for all side communications between client and server
    
    self.notify_q    : passed from main, for communication between udpServers and SideChannel.
    self.greenlets_q : tcpServers, udpServers, and SideChannel put new greenlets
                       on it and SideChannel.add_greenlets() reads them.
    self.ports_q     : to communicate with SideChannel.portCollector().
    self.logger_q    : Used for logging. replay_logger() continually reads this queue and write to file.
                       tcpdumps() writes to this queue whenever it starts/stops tcpdump.
   
    self.greenlets_q : Used for managing greenlets. add_greenlets() continually reads this queue and adds
                       new greenlets to self.greenlets.
                       This queue is passed to tcpServers, udpServers, and SideChannel so they can all put
                       new greenlets on it.
    
    self.portCollector: Used for tcpdump. tcpdumps() continually reads this queue.
                       It is passed to tcpServers, udpServers, and SideChannel.
                       tcpServer and udpServer put new coming ports on this queue (used for cleaning pcaps)
                       SideChannel puts start and stop on this queue to tell when to start/stop tcpdump process
    '''

    def __init__(self, instance, Qs, LUT, getLUT, allUDPservers, udpSenderCounts, notify_q, greenlets_q, ports_q,
                 logger_q, errorlog_q, buff_size=4096):
        self.instance = instance
        self.Qs = Qs
        self.LUT = LUT
        self.getLUT = getLUT
        self.allUDPservers = allUDPservers
        self.udpSenderCounts = udpSenderCounts
        self.notify_q = notify_q
        self.greenlets_q = greenlets_q
        self.ports_q = ports_q
        self.logger_q = logger_q
        self.errorlog_q = errorlog_q
        self.buff_size = buff_size
        self.all_clients = {}  # self.all_clients[id][replayName] = ClientObj
        self.all_side_conns = {}  # self.all_side_conns[g] = (id, replayName)
        self.id2g = {}  # self.id2g[realID]      = g
        self.greenlets = {}
        self.sleep_time = 5 * 60
        self.max_time = 5 * 60
        self.admissionCtrl = {}  # self.admissionCtrl[id][replayName] = testObj
        self.inProgress = {}  # self.inProgress[realID] = (id, replayName)
        self.replays_since_last_cleaning = []  # replays used since last cleaning
        self.uuid = UUID(Configs().get('uuidPrefixFile')) # used to generate uuid for mlab records
        if Configs().get('EC2'):
            self.instanceID = self.getEC2instanceID()
        else:
            self.instanceID = 'NonEC2'

    def run(self, server_mapping, mappings):
        '''
        SideChannel has the following methods that should be always running
        
            1- wait_for_connections: every time a new connection comes in, it dispatches a 
               thread with target=handle to take care of the connection.
            2- notify_clients: constantly gets jobs from a notify_q and notifies clients.
               This could be acknowledgment of new port (coming from UDPServer.run) or 
               notifying of a send_Q end.
        '''

        self.server_mapping_json = json.dumps(server_mapping)
        self.mappings = mappings  # [mapping, ...] where each mapping belongs to one UDPServer

        gevent.Greenlet.spawn(self.notify_clients)
        # gevent.Greenlet.spawn(self.replay_cleaner)
        gevent.Greenlet.spawn(self.add_greenlets)
        gevent.Greenlet.spawn(self.greenlet_cleaner)
        gevent.Greenlet.spawn(self.replay_logger, Configs().get('replayLog'))
        gevent.Greenlet.spawn(self.error_logger, Configs().get('errorsLog'))
        gevent.Greenlet.spawn(self.portCollector)

        self.pool = gevent.pool.Pool(10000)
        configs = Configs()
        ssl_options = gevent.ssl.create_default_context(gevent.ssl.Purpose.CLIENT_AUTH)
        if configs.is_given('sidechannel_tls_port') and configs.is_given('certs_folder'):
            certs_folder = configs.get('certs_folder')
            cert_location = os.path.join(certs_folder, 'server.crt')
            key_location = os.path.join(certs_folder, 'server.key')
            if os.path.isfile(cert_location) and os.path.isfile(key_location):
                ssl_options.load_cert_chain(cert_location, key_location)
                ssl_options.verify_mode = gevent.ssl.CERT_NONE
                self.cert_location = cert_location
                self.update_cert_expiration_metric()
            else:
                print("Https keys not found, skipping https sidechannel server")
        else:
            print("Missing https configuration, skipping https sidechannel server")

        self.http_server = gevent.server.StreamServer(self.instance, self.handle, spawn=self.pool)
        self.https_server = gevent.server.StreamServer((configs.get('publicIP'), configs.get('sidechannel_tls_port')),
                                                       self.handle, spawn=self.pool, ssl_context=ssl_options)
        gevent.Greenlet.spawn(self.run_http)

        # start the prometheus client here
        start_http_server(9990)
        # not making a separate thread since this loop keeps the main python process running
        LOG_ACTION(logger, 'https sidechannel server running')
        self.https_server.serve_forever()

    # Run the http server on a separate thread
    def run_http(self):
        LOG_ACTION(logger, 'http sidechannel server running')
        self.http_server.serve_forever()

    # Updates the prometheus cert expiration metric
    def update_cert_expiration_metric(self):
        cert_dict = gevent.ssl._ssl._test_decode_cert(self.cert_location)
        expiration_date = datetime.utcfromtimestamp(gevent.ssl.cert_time_to_seconds(cert_dict['notAfter']))
        delta_to_today = expiration_date - datetime.now()
        CERT_EXPIRATION_DAYS.set(delta_to_today.days)
        timer = Timer(60 * 60, self.update_cert_expiration_metric)
        # update the prometheus disk usage metric
        cpuPercent, memPercent, diskPercent, upLoad = getSystemStat()
        DISK_USAGE.set(diskPercent)
        timer.start()

    def handle(self, connection, address):
        '''
        Steps:
            0-  Get basic info: g, clientIP, incomingTime
            1-  Receive replay info: realID and replayName (id;replayName)
            2-  Check permission (log and close if no permission granted)
            3a- Receive iperf result
            3b- Receive mobile stats
            4-  Start tcpdump
            5a- Send server mapping to client
            5b- Send senderCount to client
            6-  Receive done confirmation from client and set success to True
            7-  Receive jitter
            8-  Receive results request and send back results
            9-  Set secondarySuccess to True and close connection
        '''
        # 0- Get basic info: g, clientIP, incomingTime, increase the counter for the number of attempted replay
        ATTEMPTED_REPLAY_COUNT.inc()
        g = gevent.getcurrent()
        clientIP = address[0]
        # incomingTime = time.strftime('%Y-%b-%d-%H-%M-%S', time.gmtime())
        incomingTime = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
        '''
        NEED TO REVISIT!!!!!!!!!
        
        For some reason, sometimes the clientIP looks weird and does not comply with either IPv4 nor IPv6 format! e.g. ::ffff:137.194.165.192
        
        This will break pcap cleaning. The below if is to fix this. It MUST be done in SideChannel.handle, TCPServer.handle, and UDPServer.handle
        '''
        if ('.' in clientIP) and (':' in clientIP):
            clientIP = clientIP.rpartition(':')[2]

        # 1- Receive replay info: realID and replayName (id;replayName)
        data = self.receive_object(connection)
        if data is None: return

        data = data.split(';')
        # realIP, is what the client get by sending 'WhatsmyIP' to the replay server
        # We use this instead of the IP address of the sidechannel,
        # since the replay might be behind a proxy that changes the IP address
        try:
            [realID, testID, replayName, extraString, historyCount, endOfTest, realIP, clientVersion] = data
            if endOfTest.lower() == 'true':
                endOfTest = True
            else:
                endOfTest = False
        except ValueError:
            [realID, testID, replayName, extraString, historyCount, endOfTest] = data
            realIP = clientIP
            clientVersion = '1.0'

        if extraString == '':
            extraString = 'extraString'

        # 1+ Receive whether changes need to be made on the server side
        # pNum, action, spec
        data = self.receive_object(connection)
        smpacNum, saction, sspec = json.loads(data)

        # 2- Check the following:
        #        -if a sideChannel with same realID is pending, kill it!
        #        -if unknown replayName
        #        -if someone else with the same IP is replaying
        LOG_ACTION(logger, 'New client: ' + '\t'.join(
            [realID, replayName, testID, extraString, historyCount, str(endOfTest)]), indent=1, action=False,
                   newLine=True)
        # If IP sent from client is different than the one we get from sidechannel, there might be a proxy, use the client
        if realIP == clientIP or realIP == '127.0.0.1':
            id = clientIP
        else:
            id = realIP

        # ClientObj should know whether there is change needed to make on this connection
        dClient = ClientObj(incomingTime, realID, id, clientIP, replayName, testID, historyCount, extraString,
                            connection, clientVersion, smpacNum, saction, sspec)
        dClient.hosts.add(id)

        # Added to support autoloadable wehe data in BQ
        dClient.uuid = self.uuid.from_socket(connection)

        # 2a- if a sideChannel with same realID is pending, kill it!
        # No two clients with the same IP can replay at the same time, the first replay has to be killed
        self.killIfNeeded(realID)

        # 2b- if unknown replayName
        if (replayName not in self.Qs["tcp"]) and (replayName not in self.Qs["udp"]):
            if not load_replay(replayName, self.Qs, self.LUT, self.getLUT, self.allUDPservers, self.udpSenderCounts):
                LOG_ACTION(logger, '*** Unknown replay name: {} ({}) ***'.format(replayName, realID))
                send_result = self.send_object(connection, '0;1')
                dClient.exceptions = 'UnknownRelplayName'
                # self.logger_q.put('\t'.join(dClient.get_info()))
                REPLAY_ERROR_COUNT.labels('unknown_name').inc()
                return
        # 2c- if server is overloaded
        cpuPercent, memPercent, diskPercent, upLoad = getSystemStat()

        LOG_ACTION(logger,
                   'Server Load right now: CPU Usage {}% Memory Usage {}% Disk Usage {}% Upload Bandwidth Usage {}Mbps with {} active connections now ***'.format(
                       cpuPercent, memPercent, diskPercent, upLoad, len(self.inProgress)))

        # Check cpu, memory and bandwidth usage
        # If any of these happens: memory > 95%, disk > 95%, bandwidth > 2000 Mbps, return 0;3
        if memPercent > 95 or diskPercent > 95 or upLoad > 2000:
            # LOG_ACTION(logger, '*** Server Overloaded : CPU Usage {}% Memory Usage {}% Upload Bandwidth Usage {}Mbps with {} active connections now ***'.format(cpuPercent, memPercent, upLoad, len(self.all_clients)))
            send_result = self.send_object(connection, '0;3')
            dClient.exceptions = 'Server Overloaded with CPU Usage {}% Memory Usage {}% Upload Bandwidth Usage {}Mbps with {} active connections now *** '.format(
                cpuPercent, memPercent, upLoad, len(self.inProgress))
            self.errorlog_q.put(dClient.exceptions)
            REPLAY_ERROR_COUNT.labels('server_overloaded').inc()
            return
        # Each client can only run one replay at any time
        # self.admissionCtrl[id] has to be unique
        # 2d- check permission
        #    if testID:
        #        -if another back2back is on file with the same realID: kill it!
        #        -if self.admissionCtrl[id] exists: another user (different realID) with the same IP is on file
        #            -if it is not alive: kill it!
        #            -else: no permission
        #        -else:
        #            -populate self.admissionCtrl and self.inProgress with new testObj
        #    else:
        #        -make the realID exists on file
        #        -update the test object
        if testID:

            try:
                old_id = self.inProgress[realID]
                del self.admissionCtrl[old_id]
                del self.inProgress[realID]
                self.killIfNeeded(realID)
            except KeyError:
                pass

            try:
                testObj = self.admissionCtrl[id]
            except KeyError:
                testObj = None

            if testObj is not None:
                if not testObj.isAlive():
                    self.killIfNeeded(testObj.realID)
                    self.admissionCtrl[id] = TestObject(clientIP, realID, replayName, testID)
                    self.inProgress[realID] = id
                    good2go = True
                else:
                    good2go = False
            else:
                good2go = True
                self.inProgress[realID] = id
                testObj = TestObject(clientIP, realID, replayName, testID)

                try:
                    self.admissionCtrl[id] = testObj
                except KeyError:
                    self.admissionCtrl[id] = {}
                    self.admissionCtrl[id] = testObj

        else:
            try:
                old_id = self.inProgress[realID]
                testObj = self.admissionCtrl[old_id]
                good2go = True
                testObj.update(testID)
            except KeyError:
                good2go = False

        if good2go:
            LOG_ACTION(logger,
                       'Yay! Permission granted: {} - {} - {}'.format(realID, historyCount, testID),
                       indent=2, action=False)
            dClient.setDump('_'.join(['server', realID, replayName, extraString, historyCount, testID]))
            try:
                self.all_clients[id][replayName] = dClient
            except KeyError:
                self.all_clients[id] = {}
                self.all_clients[id][replayName] = dClient

            self.all_side_conns[g] = (id, replayName)
            self.id2g[realID] = g

            g.link(self.side_channel_callback)
            self.greenlets_q.put((g, id, replayName, 'sc', None))
            LOG_ACTION(logger,
                       'Notifying user know about granted permission: {} - {}'.format(realID, testID),
                       indent=2, action=False)
            # Also tells the client what the number of buckets being used now
            send_result = self.send_object(connection, '1;' + clientIP + ';' + str(Configs().get('xputBuckets')))
            LOG_ACTION(logger,
                       'Done notifying user know about granted permission: {} - {}'.format(realID, testID), indent=2,
                       action=False)
        else:
            try:
                testOnFile = self.admissionCtrl[id]
                LOG_ACTION(logger,
                           '*** NoPermission. You: {} - {}, OnFile: {} - {} ***'.format(realID,
                                                                                        testID,
                                                                                        testOnFile.realID,
                                                                                        testOnFile.testID))
            except KeyError:
                LOG_ACTION(logger,
                           '*** NoPermission. You: {} - {}, OnFile: None ***'.format(realID, testID))
            send_result = self.send_object(connection, '0;2;' + str(Configs().get('xputBuckets')))
            dClient.exceptions = 'NoPermission'
            REPLAY_ERROR_COUNT.labels('no_permission').inc()
            # self.logger_q.put('\t'.join(dClient.get_info()))

        # 3a- Receive iperf result
        data = self.receive_object(connection)
        if data is None: return

        data = data.split(';')

        if data[0] == 'WillSendIperf':
            LOG_ACTION(logger, 'Waiting for iperf result for: ' + realID)
            iperfRate = self.receive_object(connection)
            if iperfRate is None: return
            dClient.iperfRate = iperfRate
            LOG_ACTION(logger, 'iperf result for {}: {}'.format(realID, iperfRate))
        elif data[0] == 'NoIperf':
            LOG_ACTION(logger, 'No iperf for: ' + realID, indent=2, action=False)

        # # 3b- Receive mobile stats
        data = self.receive_object(connection)
        if data is None: return

        data = data.split(';')

        if data[0] == 'WillSendMobileStats':
            LOG_ACTION(logger, 'Waiting for mobile stats result for: ' + realID, indent=2, action=False)
            mobileStats = self.receive_object(connection)
            if mobileStats is None: return
            # Modify mobileStats here for protecting user privacy
            # 1. reverse geolocate the GPS location, store it as another item in the locationInfo dictionary, the key is 'geoinfo'
            # 2. Truncate GPS locations to only two digits after decimal point
            mobileStats = json.loads(mobileStats)
            lat = str(mobileStats['locationInfo']['latitude'])
            lon = str(mobileStats['locationInfo']['longitude'])
            if lat != '0.0' and lon != '0.0' and lat != 'nil':
                coordinates = (float(lat), float(lon)), (float(lat), float(lon))
                geoInfo = reverse_geocode.search(coordinates)[0]
                lat = float("{0:.1f}".format(float(lat)))
                lon = float("{0:.1f}".format(float(lon)))
                mobileStats['locationInfo']['country'] = geoInfo['country']
                mobileStats['locationInfo']['city'] = geoInfo['city']
                mobileStats['locationInfo']['localTime'] = getLocalTime(incomingTime, lon, lat)
            # 1. update the carrierName with network type info
            # 2. get ISP for WiFi connections via whois lookup
            mobileStats['updatedCarrierName'] = self.getCarrierName(mobileStats['carrierName'],
                                                                    mobileStats['networkType'], clientIP)
            mobileStats['locationInfo']['latitude'] = lat
            mobileStats['locationInfo']['longitude'] = lon
            dClient.mobileStats = json.dumps(mobileStats)
            LOG_ACTION(logger, 'Mobile stats for {}: {}'.format(realID, mobileStats), indent=2, action=False)
        elif data[0] == 'NoMobileStats':
            LOG_ACTION(logger, 'No mobile stats for ' + realID, indent=2, action=False)

        # 4- Start tcpdump
        LOG_ACTION(logger,
                   'Starting tcpdump for: id: {}, historyCount: {}'.format(dClient.realID, dClient.historyCount),
                   indent=2, action=False)
        # resultsFolder = getCurrentResultsFolder()
        resultsFolder = Configs().get('tmpResultsFolder') + '/' + realID + '/'

        # print '\r\n STARTING TCPDUMP FOR THIS CLIENT'
        command = dClient.dump.start(host=dClient.ip)

        # 5a- Send server mapping to client
        send_result = self.send_object(connection, self.server_mapping_json)
        if send_result is False: return
        # 5b- Send senderCount to client
        send_result = self.send_object(connection, str(self.udpSenderCounts[replayName]))
        if send_result is False: return

        # 6- Receive done confirmation from client and set success to True
        data = self.receive_object(connection)
        if data is None: return
        data = data.split(';')
        if data[0] == 'DONE':
            pass
        elif data[0] == 'ipFlip':
            LOG_ACTION(logger, 'IP flipping detected: {}, {}'.format(dClient.realID, dClient.historyCount), indent=2,
                       action=False)
            dClient.exceptions = 'ipFlip'
            return
        elif data[0] == 'timeout':
            LOG_ACTION(logger, 'Client enforeced timeout: {}, {}'.format(dClient.realID, dClient.historyCount),
                       indent=2, action=False)
            dClient.exceptions = 'clientTimeout'
            return
        else:
            print('\nSomething weird happened! Unexpected command!\n')
            return

        dClient.success = True
        dClient.clientTime = data[1]

        # 7- Receive client throughput info
        data = self.receive_object(connection)
        if data is None: return
        if 'NoJitter' not in data:
            xput, ts = json.loads(data)
            # The last sampled throughput might be outlier since the intervals can be extremely small
            xput = xput[:-1]
            ts = ts[:-1]

            folder = resultsFolder + '/clientXputs/'
            xputFile = folder + 'Xput_{}_{}_{}.json'.format(realID, historyCount, testID)

            try:
                with open(xputFile, 'w') as writeFile:
                    json.dump((xput, ts), writeFile)
            except Exception as e:
                print(e)

        '''
        It is very important to send this confirmation. Otherwise client exits early and can
        cause permission issue when replaying back to back!
        '''
        if self.send_object(connection, 'OK') is False: return

        # 8- Receive results request and send back results
        data = self.receive_object(connection)
        if data is None: return
        data = data.split(';')

        if data[0] != 'Result':
            LOG_ACTION(logger, '\nSomething weird happened! Result\n', indent=2, action=False)
            return

        LOG_ACTION(logger, 'Received DATA: {}, endOfTest {}, testID {}'.format(data, endOfTest, testID), indent=2,
                   action=False)

        if data[1] == 'Yes':
            if self.send_reults(connection) is False: return
        elif data[1] == 'No':
            if self.send_object(connection, 'OK') is False: return

        if endOfTest or (testID == '1'):
            LOG_ACTION(logger, 'Cleaning inProgress and admissionCtrl for: ' + realID, indent=2, action=False)
            id = self.inProgress[realID]
            del self.admissionCtrl[id]
            del self.inProgress[realID]

        REPLAY_COUNT.labels(replayName).inc()

        # 9- Set secondarySuccess to True, add this replay to recent list, and close connection
        dClient.secondarySuccess = True
        if replayName not in self.replays_since_last_cleaning:
            self.replays_since_last_cleaning.append(replayName)

        folder = resultsFolder + '/replayInfo/'
        replayInfoFile = folder + 'replayInfo_{}_{}_{}.json'.format(realID, historyCount, testID)

        try:
            dClient.create_info_json(replayInfoFile)
        except Exception as e:
            print('Fail to write repayInfo into the replay info file', e, replayInfoFile)


        connection.shutdown(gevent.socket.SHUT_RDWR)
        connection.close()

    def getCarrierName(self, carrierName, networkType, clientIP):
        # get WiFi network carrierName
        if networkType == 'WIFI':
            try:
                IPrange, org = getRangeAndOrg(clientIP)
                if not org:
                    carrierName = ' (WiFi)'
                else:
                    # Remove special characters in carrierName to merge tests result together
                    carrierName = ''.join(e for e in org if e.isalnum()) + ' (WiFi)'
            except:
                logger.warn('EXCEPTION Failed at getting carrierName for {}'.format(clientIP))
                carrierName = ' (WiFi)'
        else:
            carrierName = ''.join(e for e in carrierName if e.isalnum()) + ' (cellular)'

        return carrierName

    def getEC2instanceID(self):
        try:
            return urllib.request.urlopen('http://169.254.169.254/latest/meta-data/instance-id').read()
        except:
            return None

    def killIfNeeded(self, realID):
        try:
            tmpG = self.id2g[realID]
        except KeyError:
            tmpG = None

        if tmpG is not None:
            LOG_ACTION(logger, 'Have to kill previous idle sideChannel: ' + realID, indent=2, action=False)
            tmpG.unlink(self.side_channel_callback)
            self.side_channel_callback(tmpG)
            tmpG.kill(block=True)

    def get_jitter(self, connection, outfile):
        jitters = self.receive_object(connection)
        if jitters is None:
            jitters = str(jitters)
        with open(outfile, 'wb') as f:
            f.write(jitters)
        return True

    def notify_clients(self):
        '''
        Whenever a udpServer is done sending to a client port, it puts on notify_q.
        This function continually reads notify_q and notifies clients.
        '''
        while True:
            data = self.notify_q.get()
            [id, replayName, port, command] = data

            if DEBUG == 2: print('\tNOTIFYING:', data, str(port).zfill(5))

            try:
                self.send_object(self.all_clients[id][replayName].connection, ';'.join([command, str(port).zfill(5)]))
            except KeyError:
                print("SideChannel terminated. Can't notify:", id)
                pass

    def send_object(self, connection, message, obj_size_len=10):
        try:
            connection.sendall(str(len(message)).zfill(obj_size_len).encode())
            connection.sendall(message.encode())
            return True
        except:
            return False

    def receive_object(self, connection, obj_size_len=10):
        object_size = self.receive_b_bytes(connection, obj_size_len)

        if object_size is None:
            return None

        try:
            object_size = int(object_size)
        except:
            return None

        obj = self.receive_b_bytes(connection, object_size)

        if obj:
            return obj.decode('ascii', 'ignore')
        else:
            return None

    def receive_b_bytes(self, connection, b):
        data = b''
        while len(data) < b:
            try:
                new_data = connection.recv(min(b - len(data), self.buff_size))
            except:
                return None

            if not new_data:
                return None
            data += new_data

        return data

    def send_reults(self, connection):
        result_file = 'smile.jpg'
        f = open(result_file, 'rb')
        return self.send_object(connection, f.read())

    def side_channel_callback(self, *args):
        '''
        When a side_channel greenlet exits, this function is called and 
            1- Locate client object
            2- Stops tcpdump
            3- Clean pcap (if replay successful) 
            4- Asks to kill dnagling greenlets and clean greenlets dict (buy putting the request on greenlets.q queue)  
            5- Mapping is cleaned
            6- Clean dicts
        '''

        # Locate client object
        g = args[0]
        (id, replayName) = self.all_side_conns[g]
        dClient = self.all_clients[id][replayName]

        LOG_ACTION(logger, 'side_channel_callback for: {} ({}). Success: {}, Client time: {}, historyCount: {}'.format(
            dClient.realID,
            dClient.testID,
            dClient.success,
            dClient.clientTime,
            dClient.historyCount,
        ), indent=2, action=False)

        self.greenlets_q.put((None, id, replayName, 'remove', None))

        # Clean UDP mappings (populated in UDPserver.handle)
        for mapping in self.mappings:
            for port in dClient.ports:
                try:
                    del mapping[id][port]
                except KeyError:
                    pass

        # Clean dicts
        del self.all_clients[id][replayName]
        del self.all_side_conns[g]
        del self.id2g[dClient.realID]

        # Stop tcpdump
        LOG_ACTION(logger,
                   'Stopping tcpdump for: id: {}, historyCount: {}'.format(dClient.realID, dClient.historyCount),
                   indent=2, action=False)
        tcpdumpResult = dClient.dump.stop()
        LOG_ACTION(logger, 'tcpdumpResult: {}'.format(tcpdumpResult), indent=3, action=False)

        # Create _out.pcap (only if the replay was successful and no content modification)
        if dClient.secondarySuccess:
            tcpdumpstarts = time.time()
            if dClient.exceptions != 'ContentModification':
                permResultsFolder = getCurrentResultsFolder()
                clean_pcap(dClient.dump.dump_name, dClient.id, get_anonymizedIP(dClient.id), dClient.ports,
                           dClient.realID, permResultsFolder)
                tcpdumpends = time.time()
                cpuPercent, memPercent, diskPercent, upLoad = getSystemStat()
                LOG_ACTION(logger,
                           'Cleaned pcap for id: {}, historyCount: {}; CPU Usage {}% Memory Usage {}% Disk Usage {}% Upload Bandwidth Usage {}Mbps with {} active connections and {} clients now, spent {} seconds ***'.format(
                               dClient.realID, dClient.historyCount, cpuPercent, memPercent, diskPercent, upLoad,
                               len(self.inProgress), len(self.all_clients), tcpdumpends - tcpdumpstarts), indent=2,
                           action=False)
            # recursively change the dClient results' ownership from root to user
            # makes it easier to delete after data is backed up
            if os.getenv("SUDO_UID"):
                uid = int(os.getenv("SUDO_UID"))
                for root, dirs, files in os.walk(dClient.targetFolder):
                    for dir in dirs:
                        os.chown(os.path.join(root, dir), uid, uid)
                    for file in files:
                        os.chown(os.path.join(root, file), uid, uid)

        return True

    def replay_logger(self, replay_log):
        '''
        Logs all replay activities.
        '''
        replayLogger = logging.getLogger('replayLogger')
        createRotatingLog(replayLogger, replay_log)
        # install_mp_handler(logger)
        while True:
            toWrite = self.logger_q.get()
            replayLogger.info(toWrite)

    def error_logger(self, error_log):
        '''
        Logs all errors and exceptions.
        '''

        errorLogger = logging.getLogger('errorLogger')
        createRotatingLog(errorLogger, error_log)
        # install_mp_handler(logger)

        while True:
            toWrite = self.errorlog_q.get()
            id = toWrite[0]
            toWrite = str(toWrite)

            print('\n***CHECK ERROR LOGS: {}***'.format(toWrite))

            errorLogger.info(toWrite)

    def add_greenlets(self):
        '''
        Everytime a clinet connects to the SideChannel or a TCPServer, a greenlet is spawned.
        These greenlets are added to a dictionary with timestamp (using this function) and 
        are garbage collected periodically using greenlet_cleaner() 
        '''
        while True:
            (g, clientIP, replayName, who, instance) = self.greenlets_q.get()

            # SideChannel asking to add greenlet
            if who == 'sc':
                try:
                    self.greenlets[clientIP][replayName] = {g: time.time()}
                except KeyError:
                    self.greenlets[clientIP] = {}
                    self.greenlets[clientIP][replayName] = {g: time.time()}

            # side_channel_callback asking to remove greenlet
            elif who == 'remove':
                LOG_ACTION(logger, 'Cleaning greenlets for: ' + get_anonymizedIP(clientIP), action=False, indent=2)
                try:
                    for x in self.greenlets[clientIP][replayName]:
                        x.kill(block=False)
                    del self.greenlets[clientIP][replayName]
                except KeyError:
                    pass

            # TCP/UDP servers asking to add greenlet
            else:
                try:
                    self.greenlets[clientIP][replayName][g] = time.time()
                except KeyError:
                    g.kill(block=False)
                    self.errorlog_q.put(
                        (get_anonymizedIP(clientIP), replayName, 'Unknown connection', who.upper(), instance))

    def replay_cleaner(self):
        '''
        This goes through self.Qs and delete replays that are not used since last cleaning
        '''
        while True:
            udp_replays_to_delete = []
            tcp_replays_to_delete = []

            for replayName in self.Qs["udp"]:
                if replayName not in self.replays_since_last_cleaning:
                    udp_replays_to_delete.append(replayName)

            for replayName in self.Qs["tcp"]:
                if replayName not in self.replays_since_last_cleaning:
                    tcp_replays_to_delete.append(replayName)

            LOG_ACTION(logger, "Cleaning not used replays, current total {}, to delete {}".format(
                len(self.Qs["tcp"]), udp_replays_to_delete + tcp_replays_to_delete))

            # clean TCP
            for key in tcp_replays_to_delete:
                del self.Qs["tcp"][key]
            # clean UDP
            for key in udp_replays_to_delete:
                del self.Qs["udp"][key]

            self.replays_since_last_cleaning = []
            LOG_ACTION(logger, 'Done cleaning: remaining total {}, remaining replays {}, Qs size {}'.format(len(self.Qs["tcp"]), self.Qs["tcp"].keys(), get_size(self.Qs)), indent=1, action=False)
            snapshot = tracemalloc.take_snapshot()
            display_top(snapshot)
            gevent.sleep(self.sleep_time)

    def greenlet_cleaner(self):
        '''
        This goes through self.greenlets and kills any greenlet which is 
        self.max_time seconds or older
        '''
        while True:
            LOG_ACTION(logger, 'Cleaning dangling greenlets: {}'.format(len(self.greenlets)))
            ip_need_cleaning = []
            for ip in self.greenlets:
                replay_in_progress_this_ip = False
                for replayName in list(self.greenlets[ip].keys()):

                    for g in list(self.greenlets[ip][replayName].keys()):

                        if g.successful():
                            del self.greenlets[ip][replayName][g]

                        elif time.time() - self.greenlets[ip][replayName][g] > self.max_time:
                            g.kill(block=False)
                            del self.greenlets[ip][replayName][g]

                    if len(self.greenlets[ip][replayName]) == 0:
                        del self.greenlets[ip][replayName]
                    else:
                        replay_in_progress_this_ip = True

                if not replay_in_progress_this_ip:
                    ip_need_cleaning.append(ip)

            for ip in ip_need_cleaning:
                del self.greenlets[ip]

            LOG_ACTION(logger, 'Done cleaning: {}'.format(len(self.greenlets)), indent=1, action=False)
            gevent.sleep(self.sleep_time)

    def portCollector(self):
        while True:
            (command, id, replayName, port_or_host) = self.ports_q.get()

            try:
                dClient = self.all_clients[id][replayName]
            except:
                LOG_ACTION(logger, 'portCollector cannot find client: ' + id, level='EXCEPTION', doPrint=False)
                continue

            if command == 'port':
                dClient.ports.add(port_or_host)

            elif command == 'host':
                dClient.hosts.add(port_or_host)


def timedRun(cmd, timeout_sec):
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    timer = Timer(timeout_sec, proc.kill)
    out = ''
    try:
        timer.start()
        out, stderr = proc.communicate()
    finally:
        timer.cancel()
    return out


def getRangeAndOrg(ip):
    out = timedRun(['whois', ip], 1)
    out = out.decode('ascii', 'ignore')

    IPRange = None
    orgName = None
    netRange = None

    if 'NetRange:' in out:
        netRange = out.split('NetRange:')[1].split('\n')[0]
        netRange = netRange.split()
        IPRange = neta.IPRange(netRange[0], netRange[2])


    # LACNIC/RIPE format
    elif 'inetnum:' in out:
        netRange = out.split('inetnum:')[1].split('\n')[0]
        if '/' in netRange:
            netRange = netRange.split()[0]
            IPRange = neta.IPSet(neta.IPNetwork(netRange))
        else:
            netRange = netRange.split()
            IPRange = neta.IPRange(netRange[0], netRange[2])

    # ways to extract ISP name out from the whois result
    if 'OrgName:' in out:
        orgName = out.split('OrgName:')[1].split('\n')[0]
    elif 'Organization:' in out:
        orgName = out.split('Organization:')[1].split('\n')[0]
    elif 'owner:' in out:
        orgName = out.split('owner:')[1].split('\n')[0]
    elif 'org-name:' in out:
        orgName = out.split('org-name:')[1].split('\n')[0]
    elif 'abuse-mailbox:' in out:
        orgName = out.split('abuse-mailbox:')[1].split('@')[1].split('.')[0]
    elif 'netname:' in out:
        orgName = out.split('netname:')[1].split('\n')[0]

    if orgName and netRange:
        return IPRange, orgName
    else:
        return None, None


def getLocalTime(utcTime, lon, lat):
    if (lat == lon == '0.0') or (lat == lon == 0.0) or lat == 'null':
        return None

    utcTime = datetime.strptime(utcTime, '%Y-%m-%d %H:%M:%S')

    tf = TimezoneFinder()
    # METHOD 1: from UTC
    from_zone = tz.gettz('UTC')

    to_zone = tf.timezone_at(lng=lon, lat=lat)

    to_zone = tz.gettz(to_zone)

    utc = utcTime.replace(tzinfo=from_zone)

    # Convert time zone
    convertedTime = str(utc.astimezone(to_zone))

    return convertedTime


def multiReplace(payload, regions, rpayload):
    # When rpayload is '', that means we need to replace payload with the strings stores in regions
    # e.g. regions[(1,2):'haha']
    if rpayload == '':
        for region in regions:
            L = region[0]
            R = region[1]
            payload = sReplace(payload, L, R, regions[region])
    else:
        for region in regions:
            L = region[0]
            R = region[1]
            payload = sReplace(payload, L, R, rpayload[L:R])

    return payload


def sReplace(payload, L, R, replaceS):
    # replace the bytes from L to R to replaceS
    plen = len(payload)
    if R > plen or L < 0:
        print('\n\t\t ***Attention***Payload length is ', plen, 'BUT L bond is ', L, 'R bond is', R, \
              'Returning original payload')
    else:
        LeftPad = payload[: L]
        RightPad = payload[R:]
        payload = LeftPad + replaceS + RightPad
    return payload


# Randomize the whole payload in this packet
def randomize(payload):
    plen = len(payload)
    payload = ''.join(chr(random.getrandbits(8)) for x in range(plen))

    return payload


def bin2str(chain):
    return ''.join((chr(int(chain[i:i + 8], 2)) for i in range(0, len(chain), 8)))


def str2bin(chain):
    return ''.join((bin(ord(c))[2:].zfill(8) for c in chain))


def bitInv(payload):
    bpayload = str2bin(payload)
    newb = ''
    for char in bpayload:
        if char == '0':
            newb += '1'
        else:
            newb += '0'
    newpayload = bin2str(newb)
    return newpayload


def sModify(payload, action, spec):
    if action == 'Random':
        payload = randomize(payload)

    elif action == 'Invert':
        payload = bitInv(payload)

    elif action == 'ReplaceW':
        regions = spec
        payload = multiReplace(payload, regions, '')

    elif action == 'ReplaceR':
        regions = spec
        rpayload = randomize(payload)
        payload = multiReplace(payload, regions, rpayload)

    elif action == 'ReplaceI':
        region = spec
        rpayload = bitInv(payload)
        L = region[0]
        R = region[1]
        payload = sReplace(payload, L, R, rpayload[L:R])
        # payload = multiReplace(payload, regions, rpayload)

    else:
        print('\n\t Unrecognized Action,', action, ' No ACTION taken HERE in CModify')

    return payload


def getDictDistance(headersDic1, headersDic2):
    distance = 0
    for k in list(headersDic1.keys()):
        try:
            if headersDic1[k] == headersDic2[k]:
                distance -= 1
            else:
                distance += 1
        except:
            continue
    return distance


def getClosestCSP(getLUT, headersDict):
    minDistance = 10000
    # If there is only one with the same GET request, return that
    closestCSPs = []
    for csp in getLUT:
        if headersDict['GET'] == getLUT[csp]['GET']:
            closestCSPs.append(csp)

    if len(closestCSPs) == 1:
        return closestCSPs[0]

    # If more than one, now do edit distance on headers
    if len(closestCSPs) > 0:
        toTest = closestCSPs
    # If none, do edit distance on all
    else:
        toTest = list(getLUT.keys())

    closestCSP = None

    for csp in toTest:
        distance = getDictDistance(headersDict, getLUT[csp])
        if distance < minDistance:
            minDistance = distance
            closestCSP = csp

    return closestCSP


def merge_servers(Q):
    newQ = {}
    senderCount = 0

    for csp in Q:
        originalServerPort = csp[-5:]
        originalClientPort = csp[16:21]

        if originalServerPort not in newQ:
            newQ[originalServerPort] = {}

        if originalClientPort not in newQ[originalServerPort]:
            newQ[originalServerPort][originalClientPort] = []

        newQ[originalServerPort][originalClientPort] += Q[csp]

    for originalServerPort in newQ:
        for originalClientPort in newQ[originalServerPort]:
            newQ[originalServerPort][originalClientPort].sort(key=lambda x: x.timestamp)
            senderCount += 1

    return newQ, senderCount


def load_replay(replayName, Qs, LUT, getLUT, allUDPservers, udpSenderCounts):
    replayName = replayName.replace("-", "_")
    replay_file_dirs = replayName_to_replay_file_folders(replayName)
    new_replay_LUT = {}
    new_replay_getLUT = {}
    allIPs = set()
    tcpIPs = {}

    try:
        for replay_file_dir in replay_file_dirs:
            load_server_replay(replay_file_dir, Qs, new_replay_LUT, new_replay_getLUT, allUDPservers, udpSenderCounts,
                               serialize='pickle')
            update_Qs(LUT, getLUT, allIPs, tcpIPs, Qs, new_replay_LUT, new_replay_getLUT)
        return True

    except Exception as e:
        return False


def replayName_to_replay_file_folders(replayName):
    replay_file_parent_folder = Configs().get("replay_parent_folder")
    replay_file_dirs = []
    for dir in os.listdir(replay_file_parent_folder):
        if replayName in dir:
            replay_file_dirs.append("{}/{}/".format(replay_file_parent_folder, dir))

    return replay_file_dirs


def load_server_replay(folder, Qs, LUT, getLUT, allUDPservers, udpSenderCounts, serialize='pickle'):
    if folder == '':
        return

    pickle_file = ""
    for file in os.listdir(folder):
        if file.endswith(('_server_all.' + serialize)):
            pickle_file = os.path.abspath(folder) + '/' + file
            break

    if not pickle_file:
        return

    with open(pickle_file, 'br') as server_pickle:
        Q, tmpLUT, tmpgetLUT, udpServers, tcpServerPorts, replayName = pickle.load(server_pickle)

    LOG_ACTION(logger, 'Loading for: ' + folder, pickle_file, indent=1, action=False)

    Qs['tcp'][replayName] = Q['tcp']
    Qs['udp'][replayName] = Q['udp']

    LUT[replayName] = tmpLUT
    getLUT[replayName] = tmpgetLUT

    # Calculating udpSenderCounts
    udpSenderCounts[replayName] = len(Q['udp'])

    # Adding to server list
    for serverIP in udpServers:
        if serverIP not in allUDPservers:
            allUDPservers[serverIP] = set()
        for serverPort in udpServers[serverIP]:
            allUDPservers[serverIP].add(serverPort)

    # Merging Q if original_ips is off
    if not Configs().get('original_ips'):
        Qs['udp'][replayName], udpSenderCounts[replayName] = merge_servers(Q['udp'])

    return replayName, pickle_file


def update_Qs(finalLUT, finalgetLUT, allIPs, tcpIPs, Qs, LUT, getLUT):
    for replayName in Qs['tcp']:
        for csp in Qs['tcp'][replayName]:
            sss = csp.partition('-')[2]
            ip = sss.rpartition('.')[0]
            port = sss.rpartition('.')[2]

            if ip not in tcpIPs:
                tcpIPs[ip] = set()
            if port not in tcpIPs[ip]:
                tcpIPs[ip].add(port)

    for protocol in Qs:
        for replayName in Qs[protocol]:
            for csp in Qs[protocol][replayName]:
                add_IP = csp.partition('-')[2].rpartition('.')[0]
                if add_IP not in allIPs:
                    allIPs.add(csp.partition('-')[2].rpartition('.')[0])

    for replayName in LUT:
        for protocol in LUT[replayName]:
            if protocol not in finalLUT:
                finalLUT[protocol] = {}
            for x in LUT[replayName][protocol]:
                if x not in finalLUT[protocol]:
                    finalLUT[protocol][x] = LUT[replayName][protocol][x]

    for replayName in getLUT:
        for csp in getLUT[replayName]:
            if csp not in finalgetLUT:
                finalgetLUT[csp] = getLUT[replayName][csp]

    return finalLUT, finalgetLUT, tcpIPs, allIPs


def load_Qs():
    '''
    This loads and de-serializes all necessary objects.
    
    NOTE: the parser encodes all packet payloads into hex before serializing them.
          So we need to decode them before starting the replay.
    '''
    Qs = {'tcp': {}, 'udp': {}}
    LUT = {}
    getLUT = {}
    allUDPservers = {}
    udpSenderCounts = {}
    finalLUT = {}
    finalgetLUT = {}
    allIPs = set()
    tcpIPs = {}

    folders = []
    pcap_folder = Configs().get('pcap_folder')

    if os.path.isfile(pcap_folder):
        with open(pcap_folder, 'r') as f:
            for l in f:
                folders.append(l.strip())
    else:
        folders.append(pcap_folder)

    for folder in folders:
        replay_name, pickle_file = load_server_replay(folder, Qs, LUT, getLUT, allUDPservers, udpSenderCounts, serialize='pickle')
        update_Qs(finalLUT, finalgetLUT, allIPs, tcpIPs, Qs, LUT, getLUT)
        Qs["tcp"][replay_name] = pickle_file
        Qs["udp"][replay_name] = pickle_file
        gc.collect()

    return Qs, finalLUT, finalgetLUT, allUDPservers, udpSenderCounts, tcpIPs, allIPs


def atExit(aliases, iperf):
    '''
    This function is called before the script terminates.
    It tears down all created network aliases.
    '''
    for alias in aliases:
        alias.down()

    iperf.terminate()


def run(*args):
    '''
    notify_q : Queue for udpServers and SideChannel communications
               udpServers put on it whenever they're done sending to a client port.
               SideChannel get from it and notifies clients that the port is done.
    
    server_mapping: Server mapping that's sent to client
    
    mappings:  Hold udpServers' client mapping and passed to SideChannel for cleaning
    '''
    tracemalloc.start()
    PRINT_ACTION('Reading configs and args', 0)
    configs = Configs()
    configs.set('sidechannel_port', 55555)
    configs.set('serialize', 'pickle')
    configs.set('mainPath', '/var/spool/wehe/')
    configs.set('resultsFolder', 'replay/')
    configs.set('bqSchemaFolder', '/var/spool/datatypes')
    configs.set('logsPath', '/tmp/')
    configs.set('replayLog', 'replayLog.log')
    configs.set('errorsLog', 'errorsLog.log')
    configs.set('serverLog', 'serverLog.log')
    configs.set('timing', True)
    configs.set('original_ports', True)
    configs.set('original_ips', False)
    configs.set('multiInterface', False)
    configs.set('iperf', False)
    configs.set('iperf_port', 5555)
    configs.set('publicIP', '')
    configs.set('uuidPrefixFile', '/uuid_prefix_tag.txt')
    configs.read_args(sys.argv)
    configs.check_for(['pcap_folder'])

    PRINT_ACTION('Configuring paths', 0)
    configs.set('resultsFolder', configs.get('mainPath') + configs.get('resultsFolder'))
    configs.set('replayLog', configs.get('logsPath') + configs.get('replayLog'))
    configs.set('errorsLog', configs.get('logsPath') + configs.get('errorsLog'))
    configs.set('serverLog', configs.get('logsPath') + configs.get('serverLog'))

    PRINT_ACTION('Setting up directories', 0)
    if not os.path.isdir(configs.get('mainPath')):
        os.makedirs(configs.get('mainPath'))
    if not os.path.isdir(configs.get('logsPath')):
        os.makedirs(configs.get('logsPath'))

    createRotatingLog(logger, configs.get('serverLog'))

    # This is for multi-processing safe logging
    install_mp_handler()

    configs.show_all()

    LOG_ACTION(logger, 'Starting replay server. Configs: ' + str(configs), doPrint=False)

    LOG_ACTION(logger, 'Creating variables')
    notify_q = gevent.queue.Queue()
    logger_q = gevent.queue.Queue()
    errorlog_q = gevent.queue.Queue()
    greenlets_q = gevent.queue.Queue()
    ports_q = gevent.queue.Queue()
    server_mapping = {'tcp': {}, 'udp': {}}
    mappings = []

    LOG_ACTION(logger, 'Creating results folders')
    if not os.path.isdir(configs.get('resultsFolder')):
        os.makedirs(configs.get('resultsFolder'))

    if not os.path.isdir(configs.get('tmpResultsFolder')):
        os.makedirs(configs.get('tmpResultsFolder'))

    # Create results datatype schemas (Added to support autoloadable wehe data in BQ)
    os.makedirs(configs.get('bqSchemaFolder'), exist_ok=True)
    bqResultWriter.create_replayInfo_schema()
    bqResultWriter.create_clientXputs_schema()
    bqResultWriter.create_decisions_schema()
    bqResultWriter.create_localizeDecisions_schema()

    if configs.get('iperf'):
        LOG_ACTION(logger, 'Starting iperf server')
        iperf = subprocess.Popen(['iperf', '-s'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    else:
        iperf = None

    LOG_ACTION(logger, 'Loading server queues')
    Qs, LUT, getLUT, udpServers, udpSenderCounts, tcpIPs, allIPs = load_Qs()

    LOG_ACTION(logger, 'IP aliasing')
    alias_c = 1
    aliases = []
    if configs.get('original_ips'):
        for ip in sorted(allIPs):
            aliases.append(IPAlias(ip, configs.get('NoVPNint') + ':' + str(alias_c)))
            alias_c += 1

    LOG_ACTION(logger, 'Passing aliases to atExit', indent=1, action=False)
    atexit.register(atExit, aliases=aliases, iperf=iperf)

    LOG_ACTION(logger, 'Creating and running the side channel')
    side_channel = SideChannel((configs.get('publicIP'), configs.get('sidechannel_port')), Qs, LUT, getLUT, udpServers,
                               udpSenderCounts, notify_q,
                               greenlets_q, ports_q, logger_q, errorlog_q)

    LOG_ACTION(logger, 'Creating and running UDP servers')
    ports_done = {}
    count = 0
    for ip in sorted(udpServers.keys()):
        for port in udpServers[ip]:

            port = port.zfill(5)

            if configs.get('original_ports'):
                serverPort = int(port)
            else:
                serverPort = 0

            if configs.get('original_ips'):
                server = UDPServer((ip, serverPort), Qs['udp'], notify_q, greenlets_q, ports_q, errorlog_q, LUT,
                                   side_channel.all_clients, timing=configs.get('timing'))
                server.run()
                LOG_ACTION(logger, ' '.join(
                    [str(count), 'Created socket server for', str((ip, port)), '@', str(server.instance)]),
                           level=logging.DEBUG, doPrint=False)
                mappings.append(server.mapping)
                count += 1
            elif port not in ports_done:
                server = UDPServer((configs.get('publicIP'), serverPort), Qs['udp'], notify_q, greenlets_q, ports_q,
                                   errorlog_q, LUT, side_channel.all_clients, timing=configs.get('timing'))
                server.run()
                ports_done[port] = server
                LOG_ACTION(logger, ' '.join(
                    [str(count), 'Created socket server for', str((ip, port)), '@', str(server.instance)]),
                           level=logging.DEBUG, doPrint=False)
                mappings.append(server.mapping)
                count += 1
            else:
                server = ports_done[port]

            if ip not in server_mapping['udp']:
                server_mapping['udp'][ip] = {}
            server_mapping['udp'][ip][port] = server.instance
    LOG_ACTION(logger, 'Created {} UDP socket server'.format(count), indent=1, action=False)

    LOG_ACTION(logger, 'Creating and running TCP servers')
    ports_done = {}
    count = 0
    # start a tcp server with port (55558) other than 80 or 443
    # this is used for clients behind http/s proxies
    # they need to request their "realIP", the client IP address seen on the server
    # client sends a "WHATSMYIP" message for that purpose
    # when replaying a non HTTP/S trace (e.g., Skype), client needs to contact this server for realIP
    for ip in sorted(tcpIPs.keys()):
        for port in tcpIPs[ip]:

            port = port.zfill(5)

            if configs.get('original_ports'):
                serverPort = int(port)
            else:
                serverPort = 0

            if 55557 not in ports_done:
                server = TCPServer((configs.get('publicIP'), 55557), Qs['tcp'], greenlets_q, ports_q, errorlog_q, LUT,
                                   getLUT,
                                   side_channel.all_clients, timing=configs.get('timing'))
                server.run()
                LOG_ACTION(logger, ' '.join(
                    [str(count), 'Created socket server for', str((ip, 55557)), '@', str(server.instance)]),
                           level=logging.DEBUG, doPrint=False)
                ports_done[55557] = server
                count += 1

            if configs.get('original_ips'):
                server = TCPServer((ip, serverPort), Qs['tcp'], greenlets_q, ports_q, errorlog_q, LUT, getLUT,
                                   side_channel.all_clients, timing=configs.get('timing'))
                server.run()
                LOG_ACTION(logger, ' '.join(
                    [str(count), 'Created socket server for', str((ip, port)), '@', str(server.instance)]),
                           level=logging.DEBUG, doPrint=False)
                count += 1
            elif port not in ports_done:
                server = TCPServer((configs.get('publicIP'), serverPort), Qs['tcp'], greenlets_q, ports_q, errorlog_q,
                                   LUT, getLUT, side_channel.all_clients, timing=configs.get('timing'))
                server.run()
                ports_done[port] = server
                LOG_ACTION(logger, ' '.join(
                    [str(count), 'Created socket server for port', str((ip, port)), '@', str(server.instance)]),
                           level=logging.DEBUG, doPrint=False)
                count += 1
            else:
                server = ports_done[port]

            if ip not in server_mapping['tcp']:
                server_mapping['tcp'][ip] = {}
            server_mapping['tcp'][ip][port] = server.instance
    LOG_ACTION(logger, 'Created {} TCP socket server'.format(count), indent=1, action=False)
    LOG_ACTION(logger, 'Running the side channel')
    side_channel.run(server_mapping, mappings)


def main():
    run(sys.argv)


if __name__ == "__main__":
    main()