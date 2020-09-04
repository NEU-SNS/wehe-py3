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
import matplotlib

matplotlib.use('Agg')
import sys

sys.path.append('..')
import subprocess, random, numpy
from python_lib import *
import matplotlib.pyplot as plt
import scipy.stats
from scipy.stats import ks_2samp
from scipy import interpolate, integrate

DEBUG = 0


class pcapName(object):
    def __init__(self, pcapFile):

        self.path = pcapFile
        if pcapFile[-1] == '/':
            pcapFile = pcapFile[:-1]

        if not pcapFile.endswith('.pcap'):
            self.pcap = False
            return

        self.pcap = True

        pcapFile = pcapFile.rpartition('/')[2]

        if pcapFile.endswith('_out.pcap'):
            self.out = True
        else:
            self.out = False

        info = pcapFile.split('_')
        self.takenAt = info[1]
        self.realID = info[2]
        self.clientIP = info[3]
        self.replayName = info[4]
        self.id = info[5]
        self.incomingTime = info[6]
        self.extraString = info[7]
        self.historyCount = info[8]
        self.testID = info[9]


def checkTsharkVersion(targetVersion, exit=True):
    p = subprocess.Popen(['tshark', '-v'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, err = p.communicate()
    version = output.partition('\n')[0].split()[1]

    if version.startswith(targetVersion):
        return True

    print('Your tshark version is: {}. Please install version {}'.format(version, targetVersion))
    if exit is True:
        sys.exit()

    return False


def parseTsharkXputOutput(output):
    '''
    ************ WORKS WITH tshark 1.12.1 ONLY ************
    
    Takes the output of tshark xput command, i.e. tshark -qz io,stat,interval 
    and parses the results into an ordered list 
    '''
    data_points = []
    lines = output.splitlines()
    end = lines[4].partition('Duration:')[2].partition('secs')[0].replace(' ', '')
    lines[-2] = lines[-2].replace('Dur', end)

    for l in lines:
        if '<>' not in l:
            continue

        l = l.replace('|', '')
        l = l.replace('<>', '')
        parsed = list(map(float, l.split()))
        dur = float(parsed[1]) - float(parsed[0])
        try:
            xput = round(float(parsed[-1]) / dur, 2)
        except ZeroDivisionError:
            continue
        data_points.append(xput)

    # converting to Mbits/sec
    data_points = [x * 8 / 1000000.0 for x in data_points]

    return data_points, end


def xputTshark(pcapFile, xputBuckets):
    '''
    Given a pcap the calculates total xput stats.
    '''

    dcmd = ['tshark', '-r', pcapFile, '-T', 'fields', '-e', 'frame.time_relative']
    dp = subprocess.Popen(dcmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    doutput, derr = dp.communicate()
    # tshark -r <filename> -R "tcp.stream eq <index>" -T fields -e frame.time_epoch
    duration = doutput.splitlines()[-1]
    # Dynamic xputInterval = (replay duration / # buckets)
    xputInterval = float(duration) / 100

    p = subprocess.Popen(
        ['tshark', '-r', pcapFile, '-qz', 'io,stat,' + str(xputInterval) + ',not tcp.analysis.retransmission'],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, err = p.communicate()
    output = output.decode('ascii', 'ignore')
    # output = output.decode()
    xputList, end = parseTsharkXputOutput(output)
    return xputList, end


def addOverhead(x, ethOnly=False):
    ethernetOH = 14 + 0

    y = x + ethernetOH

    if not ethOnly:
        y += (16 - (x % 16)) + 64

    return y


def adjustedXput(pcapPath, xputBuckets, ethOnly=True):
    # ADJUST xputInterval according to the time bucket value
    dcmd = ['tshark', '-r', pcapPath, '-T', 'fields', '-e', 'frame.time_relative']
    dp = subprocess.Popen(dcmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    doutput, derr = dp.communicate()
    # tshark -r <filename> -R "tcp.stream eq <index>" -T fields -e frame.time_epoch
    duration = doutput.splitlines()[-1]
    # Dynamic xputInterval = (replay duration / # buckets)
    xputInterval = float(duration) / xputBuckets

    cmd = ['tshark', '-r', pcapPath, '-qz', 'io,stat,' + str(xputInterval)]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, err = p.communicate()
    output = output.decode('ascii', 'ignore')

    # Parse tshark output
    lines = output.splitlines()
    end = lines[4].partition('Duration:')[2].partition('secs')[0].replace(' ', '')
    lines[-2] = lines[-2].replace('Dur', end)

    ts = []
    xput = []

    for l in lines:
        if '<>' not in l:
            continue

        l = l.replace('|', '')
        l = l.replace('<>', '')
        parsed = list(map(float, l.split()))

        start = float(parsed[0])
        end = float(parsed[1])
        dur = end - start

        # if dur == 0:
        if dur == 0 or ((float(parsed[-1]) / dur) * 8 / 1000000.0 == 0):
            continue

        ts.append(end)
        xput.append(float(parsed[-1]) / dur)

    xput = [x * 8 / 1000000.0 for x in xput]

    # Ignore the last data point, where the interval is less than sampling interval
    return xput[:-1], ts[:-1]


def rttTshark_TCP(pcapFile, serverIP=None, clientIP=None):
    '''
    IMPORTANT NOTE1: everything is running on PCAPs captured on the server-side,
                    hence RTT for client2server direction are extremely low and
                    does not make sense and should be ignored.
                    So for frames which we have an 'tcp.analysis.ack_rtt' for, i.e. ACK frames,
                    source IP should be client's IP (meaning client is ACKing)
    IMPORTANT NOTE2: We need to toss retransmissions first                 
    '''

    if (clientIP is None) and (serverIP is None):
        print('Please provide either client or server IP')
        sys.exit()

    cmd = ['tshark', '-r', pcapFile, '-T', 'fields', '-E', 'separator=/t', '-e', 'ip.src', '-e', 'tcp.analysis.ack_rtt']
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    #     p           = subprocess.Popen(cmd)
    output, err = p.communicate()
    #     print output
    #     print 'err:', err

    rttList = []

    for l in output.splitlines():
        l = l.split('\t')
        srcIP = l[0]

        if serverIP is not None:
            if srcIP == serverIP:
                continue

        if clientIP is not None:
            if srcIP != clientIP:
                continue

        try:
            rtt = float(l[1])
        except:
            continue

        rttList.append(rtt)

    return rttList


def list2CDF(xput):
    xput = sorted(xput)

    x = [0]
    y = [0]

    for i in range(len(xput)):
        x.append(xput[i])
        y.append(float(i + 1) / len(xput))

    return x, y


def sampleKS2(list1, list2, greater=True, alpha=0.95, sub=0.5, r=100):
    '''
    Taken from NetPolice paper:
    
    This function uses Jackknife, a commonly-used non-parametric re-sampling method, 
    to verify the validity of the K-S test statistic. The idea is to randomly select 
    half of the samples from the two original input sets and apply the K-S test on 
    the two new subsets of samples. This process is repeated r times. If the results 
    of over B% of the r new K-S tests are the same as that of the original test, we 
    conclude that the original K-S test statistic is valid.
    '''

    results = []
    accept = 0.0

    for i in range(r):
        sub1 = random.sample(list1, int(len(list1) * sub))
        sub2 = random.sample(list2, int(len(list2) * sub))
        res = ks_2samp(sub1, sub2)
        results.append(res)

        pVal = res[1]
        if greater:
            if pVal > (1 - alpha):
                accept += 1
        else:
            if pVal < (1 - alpha):
                accept += 1

    dVal_avg = numpy.average([x[0] for x in results])
    pVal_avg = numpy.average([x[1] for x in results])

    return dVal_avg, pVal_avg, accept / r


def doTests(list1, list2, alpha=0.95):
    list1_nonzero = [x for x in list1 if x > 0]
    list2_nonzero = [x for x in list2 if x > 0]
    if not list1_nonzero:
        list1 = [0] * 10
    if not list2_nonzero:
        list2 = [0] * 10

    # x1, y1 = list2CDF(list1)
    # f1 = interpolate.interp1d(y1, x1)

    # x2, y2 = list2CDF(list2)
    # f2 = interpolate.interp1d(y2, x2)

    # this essentially computes the difference between averages
    # f1 is original and f2 is the random replay
    # diffFunc = lambda x: f2(x) - f1(x)
    # (area, err) = integrate.quad(diffFunc, 0.001, 1, limit=1000)

    (xputMax1, xputMin1, xputAvg1, xputMed1, xputStd1) = (
    max(list1), min(list1), numpy.average(list1), numpy.median(list1), numpy.std(list1))
    (xputMax2, xputMin2, xputAvg2, xputMed2, xputStd2) = (
    max(list2), min(list2), numpy.average(list2), numpy.median(list2), numpy.std(list2))
    area = xputAvg2 - xputAvg1

    xputMin = min(list1 + list2)
    areaOvar = float(area) / max(xputAvg1, xputAvg2)
    (ks2dVal, ks2pVal) = ks_2samp(list1_nonzero, list2_nonzero)
    greater = True
    if ks2pVal < (1 - alpha):
        greater = False
    [dVal_avg, pVal_avg, ks2AcceptRatio] = sampleKS2(list1, list2, greater, alpha=alpha)

    return [areaOvar, ks2AcceptRatio, area, 0,
            (xputMax1, xputMin1, xputAvg1, xputMed1, xputStd1),
            (xputMax2, xputMin2, xputAvg2, xputMed2, xputStd2),
            xputMin, dVal_avg, pVal_avg, ks2dVal, ks2pVal]


def main():
    adjustedXput(sys.argv[1], 0.25)
    sys.exit()


if __name__ == "__main__":
    main()
