import tornado.ioloop
import tornado.web
import gevent, gevent.pool, gevent.server, gevent.queue, gevent.select, gevent.ssl
import os
import logging
import time
import json
import sys
import reverse_geocode
import subprocess
from datetime import datetime
from timezonefinder import TimezoneFinder
from dateutil import tz
import netaddr as neta
from threading import Timer

logger = logging.getLogger('replay_server')


def timedRun(cmd, timeout_sec):
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    timer = Timer(timeout_sec, proc.kill)
    stdout = ''
    try:
        timer.start()
        stdout, stderr = proc.communicate()
    finally:
        timer.cancel()
    return stdout


def createRotatingLog(logger, logFile):
    formatter = logging.Formatter('%(asctime)s--%(name)s--%(levelname)s\t%(message)s', datefmt='%m/%d/%Y--%H:%M:%S')
    handler = logging.handlers.TimedRotatingFileHandler(logFile, backupCount=200, when="midnight")
    # handler = MultiProcessingLog(logFile)
    handler.setFormatter(formatter)
    logger.setLevel(logging.DEBUG)
    logger.addHandler(handler)


def PRINT_ACTION(message, indent, action=True, exit=False):
    if action:
        print(''.join(['\t'] * indent) + message)
    elif exit is False:
        print(''.join(['\t'] * indent) + message)
    else:
        print('\n***** Exiting with error: *****\n', message, '\n***********************************\n')
        sys.exit()


def LOG_ACTION(logger, message, level=20, doPrint=True, indent=0, action=True, exit=False, newLine=False):
    # DEBUG
    if level == 10:
        logger.debug(message)

    # INFO
    elif level == 20:
        logger.info(message)

    # WARNING
    elif level == 30:
        logger.warning(message)

    # EROOR
    elif level == 40:
        logger.error(message)

    # CRITICAL
    elif level == 50:
        logger.critical(message)

    elif level.upper() == 'EXCEPTION':
        logger.exception(message)

    if doPrint:
        if newLine is True:
            print('\n')
        PRINT_ACTION(message, indent, action=action, exit=exit)


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


def getCurrentResultsFolder(currentResultsFolder):
    if not os.path.exists(currentResultsFolder):
        os.mkdir(currentResultsFolder)
    currentYMD = time.strftime("%Y-%m-%d", time.gmtime())
    currentY = currentYMD.split("-")[0]
    currentResultsFolder = "{}/{}/".format(currentResultsFolder, currentY)
    if not os.path.exists(currentResultsFolder):
        os.mkdir(currentResultsFolder)
    currentM = currentYMD.split("-")[1]
    currentResultsFolder = "{}/{}/".format(currentResultsFolder, currentM)
    if not os.path.exists(currentResultsFolder):
        os.mkdir(currentResultsFolder)
    currentD = currentYMD.split("-")[2]
    currentResultsFolder = "{}/{}/".format(currentResultsFolder, currentD)
    if not os.path.exists(currentResultsFolder):
        os.mkdir(currentResultsFolder)

    return currentResultsFolder


class SideChannel(object):

    def __init__(self, publicIP, sidechannelPort, sidechannelTLSPort, certsFolder, resultsFolder, buff_size=4096):
        self.logger_q = gevent.queue.Queue()
        self.errorlog_q = gevent.queue.Queue()
        self.publicIP = publicIP
        self.sidechannelPort = sidechannelPort
        self.sidechannelTLSPort = sidechannelTLSPort
        self.pool = gevent.pool.Pool(10000)
        self.resultsFolder = resultsFolder
        self.buff_size = buff_size
        ssl_options = gevent.ssl.create_default_context(gevent.ssl.Purpose.CLIENT_AUTH)
        if sidechannelTLSPort and certsFolder:
            cert_location = os.path.join(certsFolder, 'server.crt')
            key_location = os.path.join(certsFolder, 'server.key')
            if os.path.isfile(cert_location) and os.path.isfile(key_location):
                ssl_options.load_cert_chain(cert_location, key_location)
                ssl_options.verify_mode = gevent.ssl.CERT_NONE
            else:
                print("Https keys not found, skipping https sidechannel server")
        else:
            print("Missing https configuration, skipping https sidechannel server")

        self.http_server = gevent.server.StreamServer((publicIP, sidechannelPort), self.handle, spawn=self.pool)
        self.https_server = gevent.server.StreamServer((publicIP, sidechannelTLSPort),
                                                       self.handle, spawn=self.pool, ssl_context=ssl_options)

    def run(self, errorsLog):

        gevent.Greenlet.spawn(self.error_logger, errorsLog)
        gevent.Greenlet.spawn(self.run_http)

        # not making a separate thread since this loop keeps the main python process running
        LOG_ACTION(logger, 'https sidechannel server running')
        self.https_server.serve_forever()

    # Run the http server on a separate thread
    def run_http(self):
        LOG_ACTION(logger, 'http sidechannel server running')
        self.http_server.serve_forever()

    def handle(self, connection, address):
        '''
        Steps:
            1- Receive mobile stats
            2- Store mobile stats in file
        '''
        clientIP = address[0]
        if ('.' in clientIP) and (':' in clientIP):
            clientIP = clientIP.rpartition(':')[2]
        incomingTime = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
        # Receive mobile stats
        data = self.receive_object(connection)
        if data is None: return

        data = data.split(';')
        # data[0] = 'WillSendMobileStats'
        # data[1] = userID
        # data[2] = historyCount
        # data[3] = testID

        if data[0] == 'WillSendMobileStats':
            if len(data) != 4:
                LOG_ACTION(logger, 'Wrong data format for {}, {}'.format(clientIP, data), indent=2, action=False)
                return
            userID = data[1]
            historyCount = data[2]
            testID = data[3]
            LOG_ACTION(logger, 'Waiting for mobile stats result for: {} {} {} '.format(userID, historyCount, testID),
                       indent=2, action=False)
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
            mobileStats = json.dumps(mobileStats)

            resultsFolder = getCurrentResultsFolder(self.resultsFolder)

            mobileStatsFolder = resultsFolder + '/' + userID + '/mobileStats/'

            if not os.path.exists(mobileStatsFolder):
                os.makedirs(mobileStatsFolder)
            mobileStatFile = mobileStatsFolder + 'mobileStats_{}_{}_{}.json'.format(userID, historyCount, testID)
            json.dump(mobileStats, open(mobileStatFile, 'w'))
            uid = int(os.getenv("SUDO_UID"))
            os.chown(mobileStatsFolder, uid, uid)
            os.chown(mobileStatFile, uid, uid)
            LOG_ACTION(logger, 'Incoming Time {}, Mobile stats for {}: {}'.format(incomingTime, clientIP, mobileStats),
                       indent=2, action=False)
        elif data[0] == 'NoMobileStats':
            LOG_ACTION(logger, 'No mobile stats for ' + clientIP, indent=2, action=False)
        else:
            self.errorlog_q.put(('Unknown request', clientIP, data))

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
                self.errorlog_q.put('EXCEPTION Failed at getting carrierName for {}'.format(clientIP))
                carrierName = ' (WiFi)'
        else:
            carrierName = ''.join(e for e in carrierName if e.isalnum()) + ' (cellular)'

        return carrierName

    def send_object(self, connection, message, obj_size_len=10):
        try:
            connection.sendall(str(len(message)).zfill(obj_size_len))
            connection.sendall(message)
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

        return obj.decode('ascii', 'ignore')

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

    def error_logger(self, error_log):
        '''
        Logs all errors and exceptions.
        '''

        errorLogger = logging.getLogger('errorLogger')
        createRotatingLog(errorLogger, error_log)
        # install_mp_handler(logger)

        while True:
            toWrite = self.errorlog_q.get()
            toWrite = str(toWrite)

            print('\n***CHECK ERROR LOGS: {}***'.format(toWrite))

            errorLogger.info(toWrite)


def main():
    publicIP = ''
    sidechannelPort = 55555
    sidechannelTLSPort = 55556
    resultsFolder = '/data/RecordReplay/ReplayDumpsTimestamped/'
    certsFolder = './ssl/'

    createRotatingLog(logger, '/data/RecordReplay/logs/serverLog.log')

    side_channel = SideChannel(publicIP, sidechannelPort, sidechannelTLSPort, certsFolder,
                               resultsFolder)

    side_channel.run('/data/RecordReplay/logs/errorsLog.log')


if __name__ == "__main__":
    main()
