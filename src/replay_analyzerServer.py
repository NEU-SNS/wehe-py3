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


USAGE:
    sudo python replay_analyzerServer.py --port=56565 --ConfigFile=configs_local.cfg

    IMPORTANT NOTES: always run in sudo mode
#######################################################################################################
#######################################################################################################
'''

import json, datetime, logging, pickle, sys, traceback, glob
import tornado.ioloop, tornado.web
import gevent.monkey

gevent.monkey.patch_all(ssl=False)
import ssl
import gevent, gevent.pool, gevent.server, gevent.queue, gevent.select
from gevent.lock import RLock
from python_lib import *
from prometheus_client import start_http_server, Counter

import finalAnalysis as FA

POSTq = gevent.queue.Queue()

errorlog_q = gevent.queue.Queue()

logger = logging.getLogger('replay_analyzer')
DPIlogger = logging.getLogger('DPI')

'''
DPI test related part
'''

RESULT_REQUEST = Counter("request_total", "Total Number of Requests Received", ['type'])


class singleCurrTest(object):
    def __init__(self, userID, replayName, carrierName):
        global db
        # load the curr test info from database
        self.userID = userID
        self.replayName = replayName
        self.carrierName = carrierName
        # if not in currTest
        # create one database entry with initialized currTest and BAque_id
        currTest = db.getCurrTest(userID, replayName, carrierName)
        if not currTest:
            self.timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
            # currently this packet and this region is being tested
            self.currTestPacket, self.currTestLeft, self.currTestRight = getInitTest(replayName)
            # How many tests ran so far
            self.numTests = 0
            # How many packets has been tested
            self.numTestedPackets = 0
            # The binary analysis ID, uniquely identify the binary analysis entries related to this test
            self.BAque_id = int(
                int(hashlib.sha1('{}_{}_{}_{}_que'.format(userID, replayName, carrierName, self.timestamp)).hexdigest(),
                    16) % 10 ** 8)
            # The matching region ID, uniquely identify the matching region entries related to this test
            self.mr_id = int(
                int(hashlib.sha1('{}_{}_{}_{}_mr'.format(userID, replayName, carrierName, self.timestamp)).hexdigest(),
                    16) % 10 ** 8)
            db.insertCurrTest(userID, replayName, carrierName, self.timestamp, self.currTestPacket, self.currTestLeft,
                              self.currTestRight, self.numTests, self.numTestedPackets, self.BAque_id, self.mr_id)
        else:
            self.timestamp = currTest[0]['timestamp']
            self.currTestPacket = currTest[0]['currTestPacket']
            self.currTestLeft = currTest[0]['currTestLeft']
            self.currTestRight = currTest[0]['currTestRight']
            self.numTests = currTest[0]['numTests']
            self.numTestedPackets = currTest[0]['numTestedPackets']
            self.BAque_id = currTest[0]['BAque_id']
            self.mr_id = currTest[0]['mr_id']

    # insert the new test into the BAque table
    def insertBAque(self, testPacket, testLeft, testRight):
        print(('\r\n inserting BAque, ', testLeft, testRight))
        insertResult = self.db.insertBAque(self.BAque_id, testPacket, testLeft, testRight)
        if not insertResult:
            errorlog_q.put(('error inserting into BA queue', self.userID, self.replayName, self.carrierName,
                            self.BAque_id, testPacket, testLeft, testRight))

    # get the next test for this client from BAque table
    # if there is test left:
    #   update currtest accordingly return true
    #   delete the test entry from BAque table
    #   return True
    # else:
    #   return False
    def getNextTest(self):
        response = self.db.getTestBAque(self.BAque_id)
        # example ({'testRight': 286L, 'uniqtest_id': 1L, 'testLeft': 10L, 'testPacket': 'C_1', 'testq_id': 2501484L},)
        if response:
            db.delTestBAque(response[0]['uniqtest_id'])
            self.currTestPacket = response[0]['testPacket']
            self.currTestLeft = response[0]['testLeft']
            self.currTestRight = response[0]['testRight']
            return True
        else:
            print('NO NEXT TEST')
            return False

    # insert the byte into the matching region table
    # this function is called when the test region is a single byte and it is one of the matching bytes
    def insertMatchingRegion(self):
        insertResult = self.db.insertRegion(self.mr_id, self.currTestPacket, self.currTestLeft)
        if not insertResult:
            errorlog_q.put(('error inserting into BA queue', self.userID, self.replayName, self.carrierName, self.mr_id,
                            self.currTestPacket, self.currTestLeft))

    def getAllMatchingRegion(self):
        # allRes is [] if no matching region
        allRes = self.db.getMatchingRegion(self.mr_id)

        allMatching = {}
        for res in allRes:
            if res['packetNum'] not in allMatching:
                allMatching[res['packetNum']] = [res['byteNum']]
            else:
                allMatching[res['packetNum']].append(res['byteNum'])

        return allMatching

    # Update the current test info to database
    def updateCurr(self):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
        updateResult = self.db.updateCurrTest(self.userID, self.replayName, self.carrierName, timestamp,
                                              self.currTestPacket,
                                              self.currTestLeft, self.currTestRight, self.numTests,
                                              self.numTestedPackets)
        if not updateResult:
            errorlog_q.put(('error updating into current test', self.userID, self.replayName, self.carrierName))

    # Write this test result to database
    def backUpRaw(self, historyCount, testID, diffDetected):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
        insertResult = self.db.insertRawTest(self.userID, self.replayName, self.carrierName, timestamp,
                                             self.currTestPacket,
                                             self.currTestLeft, self.currTestRight,
                                             historyCount, testID, diffDetected)
        if not insertResult:
            errorlog_q.put(('error backing up this test', self.userID, self.replayName, self.carrierName,
                            self.currTestPacket, self.currTestLeft, self.currTestRight,
                            historyCount, testID, diffDetected))

    # delete the current test in database
    def delCurr(self):
        delTestQueResult = self.db.delTestQueue(self.BAque_id)
        delMatchingRegionResult = self.db.delMatchingRegion(self.mr_id)
        delCurrTestResult = self.db.delCurrTest(self.userID, self.replayName, self.carrierName)

        return delTestQueResult and delMatchingRegionResult and delCurrTestResult


'''
If DPI rule in prevTestData: return it
Else: return 'No result found', suggest client do DPIanalysis
'''


def getDPIrule(args):
    try:
        userID = args['userID'][0]
        carrierName = args['carrierName'][0]
        replayName = args['replayName'][0]
    except:
        return json.dumps({'success': False, 'error': 'required fields missing'}, cls=myJsonEncoder)

    preResult = loadPrevTest(userID, replayName, carrierName)

    if not preResult:
        # User can choose to test by sending DPIanalysis request
        return json.dumps({'success': False, 'error': 'No result found'})
    else:
        timestamp = preResult['timestamp']
        numTests = preResult['numTests']
        matchingContent = preResult['matchingContent']
        # User can still choose to re-test again by sending DPIanalysis request
        return json.dumps({'success': True,
                           'response':
                               {'timestamp': timestamp, 'DPIrule': matchingContent,
                                'numTests': numTests}}, cls=myJsonEncoder)


def loadPrevTest(userID, replayName, carrierName):
    global db
    response = db.getPreTest(userID, replayName, carrierName)
    if not response:
        return None
    else:
        return response[0]


# insert the matching content to previousTest
def insertPrevTest(cTest, matchingRules):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
    global db
    db.insertPreTest(cTest.userID, cTest.replayName, cTest.carrierName, timestamp, cTest.numTests, str(matchingRules),
                     cTest.mr_id)


def resetDPI(args):
    try:
        userID = args['userID'][0]
        carrierName = args['carrierName'][0]
        replayName = args['replayName'][0]
    except:
        return json.dumps({'success': False, 'error': 'required fields missing'}, cls=myJsonEncoder)

    cTest = singleCurrTest(userID, replayName, carrierName)
    if cTest.delCurr():
        return json.dumps({'success': True})
    else:
        return json.dumps({'success': False, 'error': 'Failed at removing current test'})


'''
Process the client Request for DPI analysis
Client sends current test status --- userID, carrierName, replayName, testedRegion, diff
Server figures out which Packet, TestRegion should this client be testing next

If there is no currTestData for the requested test:
  Initialize one, return the initial test to client
Elif the client did not perform test (either TestedRegion or diff is empty) right before requesting:
  Return whatever is in CurrTestData (what this client is supposed to test) for this test
Else:
  a. Write TestedRegion and diff into rawTestData (backup database for all tests)
  b. Figure out what to send to client (can either be the next test or test result)
'''


def processDPIrequest(args):
    try:
        userID = args['userID'][0]
        carrierName = args['carrierName'][0]
        replayName = args['replayName'][0]
        historyCount = args['historyCount'][0]
        testID = args['testID'][0]
    except:
        return json.dumps({'success': False, 'error': 'required fields missing'}, cls=myJsonEncoder)

    try:
        cTest = singleCurrTest(userID, replayName, carrierName)
        testedLeft = int(args['testedLeft'][0])
        testedRight = int(args['testedRight'][0])
    except Exception as e:
        return json.dumps({'success': False, 'error': 'error in provided fields'})

    # initial test
    if testedLeft == testedRight == -1:
        return json.dumps({'success': True,
                           'response': {'testPacket': cTest.currTestPacket, 'testRegionLeft': cTest.currTestLeft,
                                        'testRegionRight': cTest.currTestRight}}, cls=myJsonEncoder)
    # last finished test from this client should match the status in the database
    elif testedLeft == cTest.currTestLeft and testedRight == cTest.currTestRight:
        # store the test result
        diff = args['diff'][0]
        if diff == 'T':
            diff = True
        else:
            diff = False
        cTest.backUpRaw(historyCount, testID, diff)

        # nextDPItest, return None if not all tests have finished (result is not available)
        # otherwise, return value is matchingContent or strings indicate maximum number of tests reached
        matchingContent = nextDPItest(cTest, diff, replayName)
        if not matchingContent:
            return json.dumps({'success': True,
                               'response': {'testPacket': cTest.currTestPacket, 'testRegionLeft': cTest.currTestLeft,
                                            'testRegionRight': cTest.currTestRight}}, cls=myJsonEncoder)
        else:
            # Return a list of matching contents identified, probably needs to add multiple strings in the future
            # DPIrule = [{packet number : matching content}]
            DPIrule = matchingContent
            # remove/reset current test progress
            cTest.delCurr()
            # store this DPI test result into previousTestResult
            insertPrevTest(cTest, DPIrule)
            return json.dumps({'success': True,
                               'response': {'DPIrule': [DPIrule], 'numTests': cTest.numTests}}, cls=myJsonEncoder)
    else:
        return json.dumps({'success': False, 'error': 'error running reverse engineering'})


'''
Based on test result:
a. Update BAque (append more tests)
b. Move currTestPacket/currTestRegion forward (next packet OR next region in BAque)
'''


def nextDPItest(cTest, diff, replayName):
    cTest.numTests += 1
    # Break the test if reached either maximum threshold
    # Or no more test left
    maxPacketCheck = 10
    maxNumTest = 200
    testPacket = cTest.currTestPacket
    leftBar = cTest.currTestLeft
    rightBar = cTest.currTestRight
    # If diff = True aka Different than original, classification broke == matching contents are in the tested region
    # The remaining tests are kept in the BAque for each client
    # TODO, keep the HTTP structure while looking for keywords? since the HTTP structure is a big AND condition
    if diff:
        if (rightBar - leftBar) > 4:
            # Need to check both left and right sub regions
            midPoint = leftBar + (rightBar - leftBar) / 2
            cTest.insertBAque(testPacket, leftBar, midPoint)
            cTest.insertBAque(testPacket, midPoint, rightBar)
        # If only one byte tested in the packet
        # This byte belongs to matchingRegion (changing it broke classification)
        elif rightBar - leftBar == 1:
            cTest.insertMatchingRegion()
        # Else only 1 ~ 3 bytes need to be tested in this region, check each byte individually
        else:
            for testByte in range(leftBar, rightBar):
                cTest.insertBAque(testPacket, testByte, testByte + 1)
    # getNextTest updates current test
    currTestUpdated = cTest.getNextTest()
    # If no more test is needed for this packet
    if not currTestUpdated:
        matchingRegion = cTest.getAllMatchingRegion()
        # DPI rule found for this test
        if matchingRegion:
            allMatchingContent = {}
            for packet in matchingRegion:
                matchingBytes = matchingRegion[packet]
                matchingBytes.sort()
                matchingContent = getMatchingContent(replayName, matchingBytes, packet)
                allMatchingContent[packet] = matchingContent
            return allMatchingContent
        else:
            cTest.numTestedPackets += 1
            testPacket, testLeft, testRight = getInitTest(replayName, cTest.numTestedPackets)
            cTest.currTestPacket = testPacket
            cTest.currTestLeft = testLeft
            cTest.currTestRight = testRight

    # Stop DPI analysis when threshold is reached
    if cTest.numTestedPackets >= maxPacketCheck:
        return 'NO DPI for first {} pacs'.format(cTest.numTestedPackets)
    elif cTest.numTests >= maxNumTest:
        return 'NO DPI after {} tests'.format(cTest.numTests)

    cTest.updateCurr()

    return None


'''
Find the longest consecutive bytes in matchingRegion
Get the string corresponding to those bytes, and they are the matching content
'''


def getMatchingContent(replayName, matchingRegion, matchingPacket):
    consecutiveBytes = getLongestConsecutive(matchingRegion)
    side = matchingPacket.split('_')[0]
    packetNum = matchingPacket.split('_')[1]
    matchingContent = getContent(replayName, side, consecutiveBytes, packetNum)

    return matchingContent


# return a list of longest consecutive bytes
def getLongestConsecutive(allBytes):
    currLen = longestLen = 0
    currConsecutive = longestConsecutive = []
    for aByte in allBytes[1:]:
        if not currConsecutive:
            currConsecutive.append(aByte)
            currLen = 1
        # Still in a consecutive list
        elif aByte == currConsecutive[-1] + 1:
            currLen += 1
            currConsecutive.append(aByte)
        else:
            if currLen > longestLen:
                longestLen = currLen
                longestConsecutive = currConsecutive
            currLen = 1
            currConsecutive = [aByte]
    if currLen > longestLen:
        longestConsecutive = currConsecutive

    return longestConsecutive


def getCurrentResultsFolder():
    currentResultsFolder = Configs().get('resultsFolder')
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


# Load packet queues and get the contents from the corresponding bytes
def getContent(replayName, side, bytes, packetNum):
    # step one, load all packet content from client/server pickle/json
    packetNum = int(packetNum)
    pcap_folder = Configs().get('pcap_folder')
    replayDir = ''
    if os.path.isfile(pcap_folder):
        with open(pcap_folder, 'r') as f:
            for l in f.readlines():
                repleyFileName = replayName.replace('-', '_')
                if repleyFileName in l:
                    replayDir = l.strip()
                    break

    pickleServerFile = pickleClientFile = ''
    for file in os.listdir(replayDir):
        if file.endswith(".pcap_server_all.pickle"):
            pickleServerFile = file
        elif file.endswith(".pcap_client_all.pickle"):
            pickleClientFile = file
    if side == 'S' and pickleServerFile:
        serverQ, tmpLUT, tmpgetLUT, udpServers, tcpServerPorts, replayName = \
            pickle.load(open(replayDir + '/' + pickleServerFile, 'r'))

        protocol = 'tcp'
        if not serverQ['udp']:
            protocol = 'udp'
        csp = list(serverQ[protocol].keys())[0]
        response_text = serverQ[protocol][csp][packetNum - 1].response_list[0].payload.decode('hex')
        matchingContent = response_text[bytes[0]: bytes[-1] + 1]
    elif pickleClientFile:
        clientQ, udpClientPorts, tcpCSPs, replayName = \
            pickle.load(open(replayDir + '/' + pickleClientFile, 'r'))
        request_text = clientQ[packetNum - 1].payload.decode('hex')
        matchingContent = request_text[bytes[0]: bytes[-1] + 1]
    else:
        matchingContent = ''

    return matchingContent


'''
Result analysis related
'''


def processResult(results):
    # Should only be one result since unique (userID, historyCount, testID)
    result = results[0]
    areaT = Configs().get('areaThreshold')
    ks2Beta = Configs().get('ks2Beta')
    ks2T = Configs().get('ks2Threshold')

    outres = {'userID': result['userID'],
              'historyCount': result['historyCount'],
              'replayName': result['replayName'],
              'date': result['date'],
              'xput_avg_original': result['xput_avg_original'],
              'xput_avg_test': result['xput_avg_test'],
              'area_test': result['area_test'],
              'ks2pVal': result['ks2pVal']}

    outres['against'] = 'test'

    Negative = False
    # if the controlled flow has less throughput
    if result['xput_avg_test'] < result['xput_avg_original']:
        Negative = True

    # ks2_ratio test is problematic, sometimes does not give the correct result even in the obvious cases, not using it so far
    # 1.Area test does not pass and 2.With confidence level ks2Beta that the two distributions are the same
    # Then there is no differentiation
    if (result['area_test'] < areaT) and (result['ks2pVal'] > ks2T):
        outres['diff'] = 0
        outres['rate'] = 0
    # 1.Area test does pass and 2.With confidence level ks2Beta that the two distributions are not the same
    # Then there is differentiation
    elif (result['area_test'] > areaT) and (result['ks2pVal'] < ks2T):
        outres['diff'] = 2
        outres['rate'] = (result['xput_avg_test'] - result['xput_avg_original']) / min(result['xput_avg_original'],
                                                                                       result['xput_avg_test'])
    # Else inconclusive
    else:
        outres['diff'] = 1
        outres['rate'] = 0

    if Negative:
        outres['diff'] = - outres['diff']
        outres['rate'] = - outres['rate']

    return outres


'''
J'Alerte l'Arcep
Find the ReplayInfo for the user that wants to alert Arcep, add an additional field 'AlertArcep' : True
'''


def setAlert(userID, historyCount, testID):
    path = getCurrentResultsFolder()
    replayInfoDir = path + '/' + userID + '/replayInfo/'
    regexOriginal = '*_' + str(historyCount) + '_' + str(testID) + '.json'
    replayOriginal = glob.glob(replayInfoDir + regexOriginal)
    replayInfo = json.load(open(replayOriginal[0], 'r'))
    # set the 16th element, alert arcep to true
    replayInfo[15] = True
    json.dump(replayInfo, open(replayOriginal[0], 'w'))


# Logic:
# 1. Analyze using the throughputs sent by client (server creates a client decision file for the GET handle to answer client request)
# 2. Use the tcpdump trace to perform server side analysis (if tcpdump enabled)
def analyzer(userID, historyCount, testID, xputBuckets, alpha):
    resultsFolder = getCurrentResultsFolder()
    LOG_ACTION(logger, 'analyzer:{}, {}, {}'.format(userID, historyCount, testID))

    # return value is None if there is no file to analyze

    resObjClient = FA.finalAnalyzer(userID, historyCount, testID, resultsFolder,
                                    xputBuckets, alpha, side='Client')

    serverAnalysisStarts = time.time()

    resObjServer = FA.finalAnalyzer(userID, historyCount, testID, resultsFolder,
                                    xputBuckets, alpha, side='Server')

    serverAnalysisEnds = time.time()
    cpuPercent, memPercent, diskPercent, upLoad = getSystemStat()

    if (serverAnalysisEnds - serverAnalysisStarts) > 1:
        LOG_ACTION(logger,
                   'Took {} seconds for server side analysis and cleaning up for UserID {} and historyCount {} testID {} *** CPU {}% MEM {}% DISK {}% UPLOAD {}Mbps'.format(
                       serverAnalysisEnds - serverAnalysisStarts, userID, historyCount, testID, cpuPercent, memPercent,
                       diskPercent, upLoad))


def jobDispatcher(q):
    xputBuckets = Configs().get('xputBuckets')
    alpha = Configs().get('alpha')
    pool = gevent.pool.Pool()
    while True:
        userID, historyCount, testID = q.get()
        pool.apply_async(analyzer, args=(userID, historyCount, testID, xputBuckets, alpha,))


class myJsonEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            obj = obj.isoformat()
        else:
            obj = super(myJsonEncoder, self).default(obj)
        return obj


def loadAndReturnResult(userID, historyCount, testID, args):
    resultFolder = getCurrentResultsFolder()
    resultFile = (resultFolder + userID + '/decisions/' + 'results_{}_{}_{}_{}.json').format(userID, 'Client',
                                                                                             historyCount, testID)

    replayInfoFile = (resultFolder + userID + '/replayInfo/' + 'replayInfo_{}_{}_{}.json').format(userID,
                                                                                                  historyCount,
                                                                                                  testID)
    clientXputFile = (resultFolder + userID + '/clientXputs/' + 'Xput_{}_{}_{}.json').format(userID,
                                                                                             historyCount,
                                                                                             testID)
    clientOriginalXputFile = (resultFolder + userID + '/clientXputs/' + 'Xput_{}_{}_{}.json').format(userID,
                                                                                                     historyCount,
                                                                                                     0)
    # if result file is here, return result
    if os.path.isfile(resultFile) and os.path.isfile(replayInfoFile):
        results = json.load(open(resultFile, 'r'))
        info = json.load(open(replayInfoFile, 'r'))

        realID = info[2]
        replayName = info[4]
        extraString = info[5]
        incomingTime = info[0]
        # incomingTime = strftime("%Y-%m-%d %H:%M:%S", gmtime())
        areaTest = str(results[0])
        ks2ratio = str(results[1])
        xputAvg1 = str(results[4][2])
        xputAvg2 = str(results[5][2])
        ks2dVal = str(results[9])
        ks2pVal = str(results[10])

        return json.dumps({'success': True,
                           'response': {'replayName': replayName, 'date': incomingTime, 'userID': userID,
                                        'extraString': extraString, 'historyCount': str(historyCount),
                                        'testID': str(testID), 'area_test': areaTest, 'ks2_ratio_test': ks2ratio,
                                        'xput_avg_original': xputAvg1, 'xput_avg_test': xputAvg2,
                                        'ks2dVal': ks2dVal, 'ks2pVal': ks2pVal}}, cls=myJsonEncoder)
    else:
        # else if the clientXputs and replayInfo files (but not the result file) exist
        # maybe the POST request is missing, try putting the test to the analyzer queue
        if os.path.isfile(replayInfoFile) and os.path.isfile(clientXputFile) and os.path.isfile(
                clientOriginalXputFile):
            LOG_ACTION(logger, 'result not ready yet, putting into POSTq :{}, {}, {}'.format(userID, historyCount, testID))
            POSTq.put((userID, historyCount, testID))
        return json.dumps({'success': False, 'error': 'No result found'})


def getHandler(args):
    '''
    Handles GET requests.

    There are three types of requests:
    1. Latest default settings (no db operation)
    2. Differentiation test result (no db operation)
    3. DPI test results (db operations needed)

    If something wrong with the job, returns False.
    '''

    try:
        command = args['command'][0].decode('ascii', 'ignore')
    except:
        RESULT_REQUEST.labels('nocommand').inc()
        return json.dumps({'success': False, 'error': 'command not provided'})

    try:
        userID = args['userID'][0].decode('ascii', 'ignore')
    except KeyError as e:
        RESULT_REQUEST.labels('nouserID').inc()
        return json.dumps({'success': False, 'missing': str(e)})

    # Return the latest threshold for both area test and ks2 test
    RESULT_REQUEST.labels(command).inc()
    if command == 'defaultSetting':
        # Default setting for the client
        areaThreshold = 0.1
        ks2Threshold = 0.05
        ks2Ratio = 0.95
        return json.dumps({'success': True, 'areaThreshold': str(areaThreshold), 'ks2Threshold': str(ks2Threshold),
                           'ks2Ratio': str(ks2Ratio)}, cls=myJsonEncoder)

    elif command == 'singleResult':
        try:
            historyCount = int(args['historyCount'][0].decode('ascii', 'ignore'))
            testID = int(args['testID'][0].decode('ascii', 'ignore'))
        except Exception as e:
            return json.dumps({'success': False, 'error': str(e)})

        return loadAndReturnResult(userID, historyCount, testID, args)

    # Return the DPI rule
    elif command == 'DPIrule':
        return getDPIrule(args)

    # Reverse engineer the DPI rule used for classifying this App
    elif command == 'DPIanalysis':
        return processDPIrequest(args)

    elif command == 'DPIreset':
        return resetDPI(args)

    else:
        return json.dumps({'success': False, 'error': 'unknown command'})


def postHandler(args):
    '''
    Handles POST requests.

    Basically puts the job on the queue and return True.

    If something wrong with the job, returns False.
    '''
    try:
        command = args['command'][0].decode('ascii', 'ignore')
    except:
        return json.dumps({'success': False, 'error': 'command not provided'})

    try:
        userID = args['userID'][0].decode('ascii', 'ignore')
        historyCount = int(args['historyCount'][0].decode('ascii', 'ignore'))
        testID = int(args['testID'][0].decode('ascii', 'ignore'))
    except KeyError as e:
        return json.dumps({'success': False, 'missing': str(e)})
    except ValueError as e:
        return json.dumps({'success': False, 'value error': str(e)})

    if command == 'analyze':
        POSTq.put((userID, historyCount, testID))
    elif command == 'alertArcep':
        try:
            setAlert(userID, historyCount, testID)
            json.dumps({'success': True})
        except:
            errorlog_q.put(('Failed to alert', args))
            return json.dumps({'success': False, 'error': 'Failed to alert'})
    else:
        errorlog_q.put(('unknown command', args))
        return json.dumps({'success': False, 'error': 'unknown command'})

    LOG_ACTION(logger, 'Returning for POST UserID {} and historyCount {} testID {} ***'.format(
        userID, historyCount, testID))

    return json.dumps({'success': True})


class Results(tornado.web.RequestHandler):

    @tornado.web.asynchronous
    def get(self):
        pool = self.application.settings.get('GETpool')
        args = self.request.arguments
        LOG_ACTION(logger, 'GET:' + str(args))
        pool.apply_async(getHandler, (args,), callback=self._callback)

    @tornado.web.asynchronous
    def post(self):
        pool = self.application.settings.get('POSTpool')
        args = self.request.arguments
        LOG_ACTION(logger, 'POST:' + str(args))
        pool.apply_async(postHandler, (args,), callback=self._callback)

    def _callback(self, response):
        LOG_ACTION(logger, '_callback:' + str(response))
        self.write(response)
        self.finish()


def error_logger(error_log):
    '''
    Logs all errors and exceptions.
    '''

    errorLogger = logging.getLogger('errorLogger')
    createRotatingLog(errorLogger, error_log)

    while True:
        toWrite = errorlog_q.get()
        id = toWrite[0]
        toWrite = str(toWrite)

        print('\n***CHECK ERROR LOGS: {}***'.format(toWrite))

        errorLogger.info(toWrite)


'''
Get the initial test
a. which packet to change (if packetNum given, return the next packet)
b. what region to change
(*** some ISPs validate TLS length field (e.g., AT&T hangs replay when length is invalid),
thus keep the first 10 bytes untouched for DPI reverse engineering ***)
'''


def getInitTest(replayName, packetNum=0):
    packetMetaDic = Configs().get('packetMetaDic')
    packetNum = int(packetNum)
    # packetS_N is packet side_number, e.g., C_1
    packetS_N = packetMetaDic[replayName][packetNum][0]
    packetLen = packetMetaDic[replayName][packetNum][1]
    return packetS_N, 10, packetLen


def procPacketMetaLine(onePacMeta, clientIP):
    l = onePacMeta.replace('\n', '').split('\t')
    srcIP = l[5]

    if 'ip:tcp' in l[1]:
        protocol = 'tcp'
    elif 'ip:udp' in l[1]:
        protocol = 'udp'
    else:
        print('\r\n Unknown protocol!! EXITING')
        sys.exit()

    if protocol == 'tcp':
        paclength = int(l[11])
    else:
        paclength = int(l[12]) - 8  # subtracting UDP header length

    if srcIP == clientIP:
        srcSide = 'C'
    else:
        srcSide = 'S'

    return srcSide, paclength


'''
load packetMeta info from replay folders
create a dictionary with key : replayName
value : list of packets in the replay and the length of each packet
e.g. [ ('C_1', 230), ('S_1', 751), ('S_2', 182), ...]
'''


def getPacketMetaInfo():
    folders = []
    packetMetaDic = {}

    pcap_folder = Configs().get('pcap_folder')

    if os.path.isfile(pcap_folder):
        with open(pcap_folder, 'r') as f:
            for l in f:
                folders.append(l.strip())
    else:
        folders.append(pcap_folder)

    for folder in folders:
        packetList = []
        # client packet number
        packetNumC = 0
        # server packet number
        packetNumS = 0
        if folder == '':
            continue

        replayName = folder.split('/')[-1]
        if 'Random' in replayName:
            continue
        # For some reason, the filename uses '_', but replayName actually uses '-'
        replayName = replayName.replace('_', '-')

        packetMeta = folder + '/packetMeta'
        client_ip_file = folder + '/client_ip.txt'
        f = open(client_ip_file, 'r')
        client_ip = (f.readline()).strip()

        with open(packetMeta, 'r') as m:
            for line in m:
                pacSide, packetLen = procPacketMetaLine(line, client_ip)
                if packetLen == 0:
                    continue
                elif pacSide == 'C':
                    packetNumC += 1
                    packetList.append(('C_' + str(packetNumC), packetLen))
                else:
                    packetNumS += 1
                    packetList.append(('S_' + str(packetNumS), packetLen))

        packetMetaDic[replayName] = packetList

    Configs().set('packetMetaDic', packetMetaDic)


def main():
    # PRINT_ACTION('Checking tshark version', 0)
    # TH.checkTsharkVersion('1.8')
    global db

    configs = Configs()
    configs.set('xputInterval', 0.25)
    configs.set('alpha', 0.95)
    configs.set('mainPath', '/data/RecordReplay/')
    configs.set('resultsFolder', 'ReplayDumpsTimestamped/')
    configs.set('logsPath', 'logs/')
    configs.set('analyzerLog', 'analyzerLog.log')
    configs.read_args(sys.argv)
    configs.check_for(['analyzerPort'])

    PRINT_ACTION('Configuring paths', 0)
    configs.set('resultsFolder', configs.get('mainPath') + configs.get('resultsFolder'))
    configs.set('logsPath', configs.get('mainPath') + configs.get('logsPath'))
    configs.set('analyzerLog', configs.get('logsPath') + configs.get('analyzerLog'))

    PRINT_ACTION('Setting up logging', 0)
    if not os.path.isdir(configs.get('logsPath')):
        os.makedirs(configs.get('logsPath'))

    createRotatingLog(logger, configs.get('analyzerLog'))

    # install_mp_handler()
    configs.show_all()
    # this was used for DPI analysis
    # getPacketMetaInfo()

    LOG_ACTION(logger, 'Starting server. Configs: ' + str(configs), doPrint=False)

    gevent.Greenlet.spawn(error_logger, Configs().get('errorsLog'))

    g = gevent.Greenlet.spawn(jobDispatcher, POSTq)

    g.start()

    if configs.is_given('analyzer_tls_port') and configs.is_given('certs_folder'):
        certs_folder = configs.get('certs_folder')
        cert_location = os.path.join(certs_folder, 'server.crt')
        key_location = os.path.join(certs_folder, 'server.key')
        if os.path.isfile(cert_location) and os.path.isfile(key_location):
            try:
                https_application = tornado.web.Application([(r"/Results", Results), ])
                https_application.settings = {'GETpool': gevent.pool.Pool(),
                                              'POSTpool': gevent.pool.Pool(),
                                              'debug': True,
                                              }
                ssl_options = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                ssl_options.load_cert_chain(cert_location, key_location)
                ssl_options.verify_mode = ssl.CERT_NONE
                https_application.listen(configs.get('analyzer_tls_port'), ssl_options=ssl_options)
                print(("[https] listening on port %d" % configs.get('analyzer_tls_port')))
            except:
                print("There was an error launching the https server")
        else:
            print("Https keys not found, skipping https server")
    else:
        print("Missing https configuration, skipping https server")

    application = tornado.web.Application([(r"/Results", Results),
                                           ])

    application.settings = {'GETpool': gevent.pool.Pool(),
                            'POSTpool': gevent.pool.Pool(),
                            'debug': True,
                            }

    application.listen(configs.get('analyzerPort'))
    print(("[http]  listening on port %d" % configs.get('analyzerPort')))
    start_http_server(9091)
    tornado.ioloop.IOLoop.instance().start()


if __name__ == "__main__":
    main()
