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

import subprocess, numpy, datetime, json, logging, traceback
import matplotlib
import copy

matplotlib.use('Agg')
import sys, glob, pickle, os, time

sys.path.append('testHypothesis')
import matplotlib.pyplot as plt
import testHypothesis as TH

DEBUG = 0


elogger = logging.getLogger('errorLogger')


class ResultObj(object):
    def __init__(self, userID, historyCount, testID, replayName, extraString, date=None):
        self.userID = str(userID)
        self.historyCount = int(historyCount)
        self.testID = int(testID)
        self.replayName = replayName
        self.extraString = extraString
        self.xput_avg_original = -1
        self.xput_avg_test = -1
        self.area_test = -1
        self.ks2_ratio_test = -1
        self.ks2dVal = -1
        self.ks2pVal = -1
        if not date:
            self.date = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())
        else:
            self.date = date

    def tuplify(self):
        dTuple = str(
            tuple(map(str, [self.userID, self.historyCount, self.testID, self.extraString, self.date, self.replayName,
                            self.xput_avg_original, self.xput_avg_test,
                            self.area_test, self.ks2_ratio_test, self.ks2dVal, self.ks2pVal])))
        return dTuple


def finalAnalyzer(userID, historyCount, testID, path, alpha, side="Client"):
    replayInfodir = path + '/' + userID + '/replayInfo/'
    regexOriginal = '*_' + str(historyCount) + '_' + str(0) + '.json'
    regexTest = '*_' + str(historyCount) + '_' + str(testID) + '.json'
    replayInfoOriginal = glob.glob(replayInfodir + regexOriginal)
    replayInfoTest = glob.glob(replayInfodir + regexTest)
    if replayInfoOriginal:
        replayInfo = json.load(open(replayInfoOriginal[0], 'r'))
    elif replayInfoTest:
        replayInfo = json.load(open(replayInfoTest[0], 'r'))
    else:
        replayInfo = ["", "", "", "", "", ""]

    realID = replayInfo[2]
    replayName = replayInfo[4]
    extraString = replayInfo[5]
    incomingTime = replayInfo[0]

    folder = path + '/' + userID + '/clientXputs/'
    regexOriginal = '*_' + str(historyCount) + '_' + str(0) + '.json'
    regexRandom = '*_' + str(historyCount) + '_' + str(testID) + '.json'
    fileOriginal = glob.glob(folder + regexOriginal)
    fileRandom = glob.glob(folder + regexRandom)
    try:
        (xputO, durO) = json.load(open(fileOriginal[0], 'r'))
        (xputR, durR) = json.load(open(fileRandom[0], 'r'))
    except Exception as e:
        elogger.error('FAIL at loading the client xputs {} {} {}', userID, historyCount, testID)
        return None

    try:
        resultFile = (path + '/' + userID + '/decisions/' + 'results_{}_{}_{}_{}.json').format(userID, side,
                                                                                               historyCount, testID)
        # xputO = [x for x in xputO if x > 0]
        # xputR = [x for x in xputR if x > 0]
        # Only use none-zero throughputs for test
        forPlot, results = testIt(xputO, xputR, resultFile, alpha)
    except Exception as e:
        elogger.error('FAIL at testing the result for {} {} {}'.format(userID, historyCount, testID))
        return None

    resultObj = ResultObj(realID, historyCount, testID, replayName, extraString, incomingTime)

    return resultObj


def plotCDFs(xLists, outfile):
    colors = ['r', 'b', 'g', 'b']
    plt.clf()

    i = -1
    j = 0
    for traceName in list(xLists.keys()):
        i += 1
        j += 3
        x, y = TH.list2CDF(xLists[traceName])
        plt.plot(x, y, '-', color=colors[i % len(colors)], linewidth=2, label=traceName)

    plt.ylim((0, 1.1))

    plt.legend(loc='best', prop={'size': 8})
    plt.grid()
    plt.title(outfile.rpartition('/')[2])
    plt.xlabel('Xput (Mbits/sec)')
    plt.ylabel('CDF')
    plt.savefig(outfile)


def testIt(xputO, xputR, resultFile, alpha):
    forPlot = {}

    results = TH.doTests(xputO, xputR, alpha)
    with open(resultFile, "w") as writeFile:
        json.dump(results, writeFile)

    forPlot['Original'] = xputO
    forPlot['Control'] = xputR

    areaTest = results[0]
    ks2ratio = results[1]
    xputAvg1 = results[4][2]
    xputAvg2 = results[5][2]
    ks2dVal = results[9]
    ks2pVal = results[10]
    return forPlot, {'areaTest': areaTest, 'ks2ratio': ks2ratio, 'xputAvg1': xputAvg1,
                     'xputAvg2': xputAvg2, 'ks2dVal': ks2dVal, 'ks2pVal': ks2pVal}


def parseTsharkTransferOutput(output):
    '''
    ************ WORKS WITH tshark 1.12.1 ONLY ************
    '''
    x = []
    y = []
    lines = output.splitlines()

    total = 0

    for l in lines:
        if '<>' not in l:
            continue

        l = l.replace('|', '')
        l = l.replace('<>', '')
        parsed = list(map(float, l.split()))
        end = parsed[1]
        bytes = parsed[-1]

        total += bytes

        x.append(end)
        y.append(total)

    # converting to Mbits/sec
    y = [z / 1000000.0 for z in y]

    return x, y
