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

#######################################################################################################
#######################################################################################################
'''

import pickle, replay_client, urllib.request, urllib.error, urllib.parse, urllib.request, urllib.parse, urllib.error
from python_lib import *
from collections import deque

'''
This is the main script for Classifiers Unclassified
1. Run original replay
2. Run random/bit inverted replay
3. If differentation detected, perform binary search to identify the matching rule
'''

Replaycounter = 0

logger = logging.getLogger('classifierUnclassified')
formatter = logging.Formatter('%(asctime)s--%(levelname)s\t%(message)s', datefmt='%m/%d/%Y--%H:%M:%S')
handler = logging.handlers.TimedRotatingFileHandler('unclassify.log', backupCount=200, when="midnight")
# handler = logging.FileHandler('unclassify.log')
handler.setFormatter(formatter)
logger.setLevel(logging.DEBUG)
logger.addHandler(handler)


class AnalyzerI(object):
    '''
    This class contains all the methods to interact with the analyzerServer
    '''

    def __init__(self, ip, port):
        self.path = ('http://'
                     + ip
                     + ':'
                     + str(port)
                     + '/Results')

    def ask4analysis(self, id, historyCount, testID):
        '''
        Send a POST request to tell analyzer server to analyze results for a (userID, historyCount)

        server will send back 'True' if it could successfully schedule the job. It will
        return 'False' otherwise.

        This is how and example request look like:
            method: POST
            url:    http://54.160.198.73:56565/Results
            data:   userID=KSiZr4RAqA&command=analyze&historyCount=9
        '''
        # testID specifies the test number in this series of tests
        # testID = 0 is the first replay in this series of tests, thus it is the baseline (original) to be compared with
        data = {'userID': id, 'command': 'analyze', 'historyCount': historyCount, 'testID': testID}
        res = self.sendRequest('POST', data=data)
        return res

    def getSingleResult(self, id, historyCount, testID):
        '''
        Send a GET request to get result for a historyCount and testID

        This is how an example url looks like:
            method: GET
            http://54.160.198.73:56565/Results?userID=KSiZr4RAqA&command=singleResult&historyCount=9
        '''
        # testID specifies the test number in this series of tests
        data = {'userID': id, 'command': 'singleResult', 'testID': testID}

        if isinstance(historyCount, int):
            data['historyCount'] = historyCount

        res = self.sendRequest('GET', data=data)
        return res

    def sendRequest(self, method, data=''):
        '''
        Sends a single request to analyzer server
        '''
        data = urllib.parse.urlencode(data)

        if method.upper() == 'GET':
            req = urllib.request.Request(self.path + '?' + data)

        elif method.upper() == 'POST':
            data = data.encode("utf-8")
            req = urllib.request.Request(self.path, data)

        else:
            return "unknown method"
        res = urllib.request.urlopen(req).read().decode('ascii', 'ignore')
        print('\r\n RESULTS', res)
        return json.loads(res)


def processResult(result):
    # Only if ks2ratio > ks2Beta (this is the confidence interval) the ks2 result is trusted, otherwise only the area test is used
    # Default suggestion: areaThreshold 0.1, ks2Beta 95%, ks2Threshold 0.05
    # KS2:
    # ks2Threshold is the threshold for p value in the KS2 test, if p greater than it, then we cannot
    # reject the hypothesis that the distributions of the two samples are the same
    # If ks2pvalue suggests rejection (i.e., p < ks2Threshold), where accept rate < (1 - ks2Beta), the two distributions are not the same (i.e., differentiation)
    # Else, the two distributions are the same, i.e., no differentiation
    # Area:
    # if area_test > areaThreshold, the two distributions are not the same (i.e., Differentiation)
    # Else, the two distributions are the same, i.e., no differentiation
    # Return result score, 0  : both suggests no differentiation
    #                      1  : inconclusive conclusion from two methods (Considered as no differentiation so far)
    #                      2  : both suggests differentiation
    #                      if target trace has less throughput, return negative value respectively, e.g., -1 means target trace is throttled
    #        result rate: differentiated rate = (normal - throttled)/throttled

    areaT = Configs().get('areaThreshold')
    ks2Beta = Configs().get('ks2Beta')
    ks2T = Configs().get('ks2Threshold')

    ks2Ratio = float(result['ks2_ratio_test'])
    ks2Result = float(result['ks2pVal'])
    areaResult = float(result['area_test'])

    # Trust the KS2 result:
    if ks2Ratio > ks2Beta:
        # 1. The CDFs have less than areaT difference in area test and 2.With confidence level ks2T that the two distributions are the same
        # Then there is no differentiation
        if (areaResult < areaT) and (ks2Result > ks2T):
            outres = 0
        # 1. The CDFs have more than areaT difference in area test and 2.With confidence level ks2T that the two distributions are not the same
        # Then there is differentiation
        elif (areaResult > areaT) and (ks2Result < ks2T):
            outres = 2
            # rate = (result['xput_avg_test'] - result['xput_avg_original'])/min(result['xput_avg_original'], result['xput_avg_test'])
        # Else inconclusive
        else:
            outres = 1
            PRINT_ACTION('##### INConclusive Result, area test is' + str(areaResult) + 'ks2 test is ' + str(ks2Result),
                         0)
            # rate = (result['xput_avg_test'] - result['xput_avg_original'])/min(result['xput_avg_original'], result['xput_avg_test'])
    # The KS2 result is not trusted
    else:
        if areaResult > areaT:
            outres = 2
        else:
            outres = 0

    return outres


# This function would run replay client against the replay server for one time
# The tricky part is to get the classification result, the method now is to write into the 'Result.txt' file


def runReplay(PcapDirectory, pacmodify, analyzerI):
    global Replaycounter

    classification = None

    cmpacNum = -1
    caction = None
    cspec = None
    smpacNum = -1
    saction = None
    sspec = None

    Side, Num, Action, Mspec = pickle.loads(pacmodify)

    if Side == 'Client':
        cmpacNum = Num
        caction = Action
        cspec = Mspec
    elif Side == 'Server':
        smpacNum = Num
        saction = Action
        sspec = Mspec

    configs = Configs()
    testID = int(configs.get('testID'))
    configs.set('testID', str(testID + 1))

    # replay_client.run(configs = configs, pcapdir = PcapDirectory, cmpacNum = cmpacNum, caction = caction, cspec = cspec,
    #                       smpacNum = smpacNum, saction = saction, sspec = sspec)
    try:
        replayResult = replay_client.run(configs=configs, pcapdir=PcapDirectory, cmpacNum=cmpacNum, caction=caction,
                                         cspec=cspec,
                                         smpacNum=smpacNum, saction=saction, sspec=sspec, testID=configs.get('testID'),
                                         byExternal=True)
    except:
        print('\r\n Error when running replay')
        replayResult = None

    time.sleep(5)
    permaData = PermaData()
    try:
        PRINT_ACTION(str(analyzerI.ask4analysis(permaData.id, permaData.historyCount, configs.get('testID'))), 0)
    except Exception as e:
        PRINT_ACTION('\n\n\n####### COULD NOT ASK FOR ANALYSIS!!!!! #######\n\n\n' + str(e), 0)
    PRINT_ACTION(str(replayResult), 0)

    # ASK the replay analyzer for KS2 result, i.e., analyzerResult
    # replayResult is whether the replay finished, used for testing censorship
    # Classify_result = (replayResult, analyzerResult)

    # Give 5s for the server to process the result and insert metrics into the database
    time.sleep(5)
    PRINT_ACTION('Fetching analysis result from the analyzer server', 0)
    res = analyzerI.getSingleResult(permaData.id, permaData.historyCount, configs.get('testID'))

    # Check whether results are successfully fetched

    if res['success']:
        # Process result here
        pres = processResult(res['response'])
        if pres == 1:
            PRINT_ACTION('INConclusive Result. Need to re-run experiment', 0)
            classification = None
        elif pres == 2:
            PRINT_ACTION('Different from Original replay', 0)
            classification = 'NotOriginal'
        else:
            PRINT_ACTION('NOT Different from Original replay', 0)
            classification = 'Original'
    else:
        # Only use whether the replayResult as classification
        PRINT_ACTION('\r\n Failed in fetching result ' + res['error'], 0)
        classification = replayResult

    # TODO Supplement YOUR OWN method to get the classification result here

    # OR Manually type what this traffic is classified as
    # classification = raw_input('Is it classified the same as original replay? "YES" or "NO"?')

    # In our testbed
    # Run miniterm_m.py, which would read the classification result from middlebox and write it into a file called out.txt
    # subprocess.call('sudo python miniterm_m.py --cr -b 19200 /dev/ttyS0', stdout=subprocess.PIPE , shell=True)
    # dport = 80
    # time.sleep(1)
    # keyword = ':' + str(dport)
    # try:
    #     if os.path.isfile('out.txt'):
    #         with open('out.txt', 'r') as f:
    #             for line in f.readlines():
    #                 if keyword in line:
    #                     classify_result = line.split(':')[0]
    #     subprocess.call('sudo rm out.txt', stdout=subprocess.PIPE , shell=True)
    # except:
    #     print '\n\t ********Exception when getting classification result!'
    #     classification = 'Wrong!'
    #
    # print '\r\n This replay is ',classify_result

    return classification


# This function looks into the regions in question one by one
# Each suspect region only has less than 4 bytes, filtered by the previous process
def detailAnalysis(PcapDirectory, Side, PacketNum, Length, original, analysisRegion, analyzerI):
    LeftB = analysisRegion[0][0]
    RightB = analysisRegion[0][1]
    Masked = analysisRegion[1]
    noEffect = []
    hasEffect = []
    for num in range(RightB - LeftB):
        newMask = list(Masked)
        newMask.append((LeftB + num, LeftB + num + 1))
        pacmodify = pickle.dumps((Side, PacketNum, 'ReplaceI', newMask))
        Classi = Replay(PcapDirectory, pacmodify, analyzerI)
        if Classi == original:
            noEffect.append(LeftB + num)
        else:
            hasEffect.append(LeftB + num)

    return hasEffect


# RPanalysis stands for Random Payload analysis, which does the binary randomization to locate the matching contents
# It would return the key regions by randomizing different part of the payload
# The key regions are the regions that trigger the classification
def RPanalysis(PcapDirectory, Side, PacketNum, Length, original, analyzerI):
    allRegions = []
    # RAque is the queue that stores the analysis that are needed to run
    # each element of the queue is a pair of a. (pair of int) and b. (list of pairs): ((x,y),[(a,b),(c,d)])
    # (x,y) is the suspected region, meaning somewhere in this region triggers the classification
    # [(a,b),(c,d)] is the list of regions that we know does not have effect, so those region would be randomized
    # We would randomize half of the bytes in (x,y), and enqueue the new region based on the result of replaying both halves
    RAque = deque()
    # Initialization
    RAque.append(((0, Length), []))
    analysis = RAque.popleft()
    # While the length of each suspected region is longer than 4, we need to keep doing the binary randomization
    while analysis[0][1] - analysis[0][0] > 4:
        # The process might fail if we did not get the correct classification result
        # e.g. both left and right regions does not trigger classification
        # Log the results in RAque to RAque.txt before each test
        # If the process breaks somehow, we still have the latest screenshot of we have tested
        # We can then 1. Re-run the latest tests 2. manually check what went wrong
        LeftBar = analysis[0][0]
        RightBar = analysis[0][1]
        MidPoint = LeftBar + (RightBar - LeftBar) / 2
        MaskedRegions = analysis[1]
        LeftMask = list(MaskedRegions)
        RightMask = list(MaskedRegions)
        LeftMask.append((LeftBar, MidPoint))
        RightMask.append((MidPoint, RightBar))

        # print '\n\t  PREPARING LEFT MASK',MaskedRegions,LeftMask
        lpacmodify = pickle.dumps((Side, PacketNum, 'ReplaceI', LeftMask))
        LeftClass = Replay(PcapDirectory, lpacmodify, analyzerI)
        # print '\n\t  PREPARING RIGHT MASK',MaskedRegions,RightMask
        rpacmodify = pickle.dumps((Side, PacketNum, 'ReplaceI', RightMask))
        RightClass = Replay(PcapDirectory, rpacmodify, analyzerI)

        # Four different cases
        if LeftClass == original and RightClass != original:
            RAque.append(((MidPoint, RightBar), LeftMask))

        elif LeftClass != original and RightClass == original:
            RAque.append(((LeftBar, MidPoint), RightMask))

        elif LeftClass != original and RightClass != original:
            RAque.append(((LeftBar, MidPoint), MaskedRegions))
            RAque.append(((MidPoint, RightBar), MaskedRegions))

        else:
            allRegions = ['Both sides are not differentiated when masked', LeftMask, RightMask]
            logger.error(
                'Just Checked Regions {} and {}, both regions are classified the same as {}, RAque so far is {}'.format(
                    LeftMask, RightMask, LeftClass, RAque))
            break

        # LOG INFO: Which region is being checked, , Results of this pair of tests, RAque so far
        logger.info(
            'Just Checked Regions {} and {}, results are {} and {}, RAque so far is {}'.format(LeftMask, RightMask,
                                                                                               LeftClass, RightClass,
                                                                                               RAque))

        analysis = RAque.popleft()

    if allRegions != []:
        return allRegions

    else:
        # Put the last poped element back
        RAque.appendleft(analysis)
        logger.info('Starting detailed analysis, RAque so far is {}'.format(RAque))
        for region in RAque:
            effectRegion = detailAnalysis(PcapDirectory, Side, PacketNum, Length, original, region, analyzerI)
            allRegions.append(effectRegion)
            logger.info(
                'In detailed analysis, Just Checked Regions {}, effective region is {}, all effective region is now {}, RAque so far is {}'.format(
                    region, effectRegion, allRegions, RAque))

    return allRegions


# This function inform the server to get ready for another replay
# The last parameter specifies whether we need to bring up the liberate proxy for this replay
def Replay(PcapDirectory, pacmodify, AnalyzerI):
    global Replaycounter
    Replaycounter += 1
    # Repeat the experiment for 10 times, until we get a classification result, otherwise just
    classification = None
    for i in range(10):
        classification = runReplay(PcapDirectory, pacmodify, AnalyzerI)
        time.sleep(5)
        if classification != None:
            break
        if i == 9:
            print("\r\n Can not get the classification result after the 10th trial, exiting")
            sys.exit()

    return classification


# This would do a full analysis on one side of the conversation
# Look into the payload by binary randomization
# If the key regions can be found in the payload
#    record those regions
def FullAnalysis(PcapDirectory, meta, Classi_Origin, Side, analyzerI):
    Analysis = {}
    for packetNum in range(len(meta[Side])):
        Analysis[packetNum] = []
        # Do Binary Randomization
        regions = RPanalysis(PcapDirectory, Side, packetNum + 1, meta[Side][packetNum], Classi_Origin, analyzerI)
        RPresult = ['DPI based differentiation, matching regions:', regions]
        Analysis[packetNum] = RPresult

    return Analysis


# Get the flow info into a list
# e.g. [c0,c1,s0] means the whole flow contains 2 client packet and 1 server packet
def extractMetaList(meta):
    FullList = []
    for cnt in range(len(meta['Client'])):
        FullList.append('c' + str(cnt))
    for cnt in range(len(meta['Server'])):
        FullList.append('s' + str(cnt))

    return FullList


# For the lists inside, if the two consecutive lists contain memebers that are consecutive, we combine them together
# For example, [1,2], [3,4,5], [7,8]
# Would become [1,2,3,4,5], [7,8]
def CompressLists(Alists):
    lastNum = 0
    CompressedLists = []
    for Alist in Alists:
        if Alist[0] == (lastNum + 1):
            lastList = CompressedLists.pop(-1)
            CompressedLists.append(lastList + Alist)
            lastNum = Alist[-1]
        else:
            CompressedLists.append(Alist)
            lastNum = Alist[-1]
    return CompressedLists


# Compress the meta by combining consecutive regions for extracting keywords
def CompressMeta(Meta):
    CMeta = {}
    for packetNum in Meta:
        decision = Meta[packetNum]
        # If the payload of this packet is used by DPI
        if 'DPI' in decision[0]:
            CompressedLists = CompressLists(decision[1])
            CMeta[packetNum] = CompressedLists
        # Else, do not change anything
        else:
            CMeta[packetNum] = Meta[packetNum]
    return CMeta


def ExtractKeywordServer(clientport, serverQ, Prot, ServerAnalysis):
    for P in list(serverQ.keys()):
        if serverQ[P] != {}:
            Prot = P
    csp = list(serverQ[Prot].keys())[0]
    sMeta = CompressMeta(ServerAnalysis)
    # Get the keywords that are being matched on
    MatchingPackets = {}
    for Pnum in sMeta:
        keywords = []
        fields = []
        field = 'NotHTTP'
        for Alist in sMeta[Pnum]:
            start = Alist[0]
            end = Alist[-1] + 1
            # We get the keyword from each sub field
            if Prot == 'udp':
                response_text = serverQ[Prot][csp][Pnum].payload.decode('hex')
                keyword = response_text[start: end]
            else:
                response_text = serverQ[Prot][csp][Pnum].response_list[0].payload.decode('hex')
                keyword = serverQ[Prot][csp][Pnum].response_list[0].payload.decode('hex')[start: end]
                if clientport == '00080':
                    e = end
                    s = start
                    for i in range(end, len(response_text) - 1):
                        if response_text[i: i + 2] == '\r\n':
                            e = i
                            break

                    for j in range(start, 1, -1):
                        if response_text[j - 2: j] == '\r\n':
                            s = j
                            break

                    if s != 1 and e != len(response_text) - 1:
                        fullheader = response_text[s:e]
                        field = fullheader.split(' ')[0]
            # keywords contains all the keywords matched in this packet
            keywords.append(keyword)
            fields.append(field)
        MatchingPackets[Pnum] = {'fields': fields, 'keywords': keywords}

    return MatchingPackets


# Extract the corresponding contents for the matching bytes
def ExtractKeywordClient(clientport, clientQ, ClientAnalysis):
    cMeta = CompressMeta(ClientAnalysis)
    # Get the keywords that are being matched on
    MatchingPackets = {}
    for Pnum in cMeta:
        keywords = []
        fields = []
        for Alist in cMeta[Pnum]:
            start = Alist[0]
            end = Alist[-1] + 1
            # We get the keyword from each sub field
            request_text = clientQ[Pnum].payload.decode('hex')
            keyword = request_text[start: end]
            field = 'NotHTTP'
            if clientport == '00080' and request_text.startswith('GET'):
                e = end
                s = start
                for i in range(end, len(request_text) - 1):
                    if request_text[i: i + 2] == '\r\n':
                        e = i
                        break

                for j in range(start, 1, -1):
                    if request_text[j - 2: j] == '\r\n':
                        s = j
                        break

                if s != 1 and e != len(request_text) - 1:
                    fullheader = request_text[s:e]
                    field = fullheader.split(' ')[0]

            # keywords contains all the keywords matched in this packet
            keywords.append(keyword)
            fields.append(field)
        MatchingPackets[Pnum] = {'fields': fields, 'keywords': keywords}
    # We return a dictionary of packet to keywords and fields
    # e.g. MatchingPackets = {0: {'keywor


def setUpConfig(configs):
    configs.set('ask4analysis', False)
    configs.set('analyzerPort', 56565)
    configs.set('testID', '-1')
    configs.set('areaThreshold', 0.1)
    configs.set('ks2Threshold', 0.05)
    configs.set('ks2Beta', 0.95)

    configs.read_args(sys.argv)
    return configs


def main(args):
    # All the configurations used
    configs = Configs()
    configs = setUpConfig(configs)

    if args == []:
        configs.read_args(sys.argv)
    else:
        configs.read_args(args)

    configs.check_for(['pcap_folder'])

    # The following does a DNS lookup and resolves server's IP address
    try:
        configs.get('serverInstanceIP')
    except KeyError:
        configs.check_for(['serverInstance'])
        configs.set('serverInstanceIP', Instance().getIP(configs.get('serverInstance')))

    PcapDirectory = configs.get('pcap_folder')

    if not PcapDirectory.endswith('/'):
        PcapDirectory = PcapDirectory + '/'

    permaData = PermaData()
    permaData.updateHistoryCount()
    analyzerI = AnalyzerI(configs.get('serverInstanceIP'), configs.get('analyzerPort'))

    # STEP 1
    # No modification, get original Classification
    nomodify = pickle.dumps(('Client', -1, None, None))
    PRINT_ACTION('Start to replay Original trace', 0)
    Classi_Origin = Replay(PcapDirectory, nomodify, analyzerI)

    print('\r\n %%%%%%%%%% JUST FINISHED ORIGINAL REPLAY')
    time.sleep(5)
    # Load the randomized trace and perform a replay to check whether DPI based classification
    PRINT_ACTION('Start to replay Randomized trace', 0)

    print((PcapDirectory.split('_')[0] + 'Random_' + PcapDirectory.split('_')[1]))
    if '_' in PcapDirectory:
        Classi_Random = Replay(PcapDirectory.split('_')[0] + 'Random_' + PcapDirectory.split('_')[1], nomodify,
                               analyzerI)
    else:
        Classi_Random = Replay(PcapDirectory[:-1] + 'Random/', nomodify, analyzerI)

    if Classi_Origin == Classi_Random:
        PRINT_ACTION(
            'NO DPI based differentiation detected. Both original trace and randomized trace are classified the same',
            0)
        sys.exit()


if __name__ == "__main__":
    main(sys.argv)
