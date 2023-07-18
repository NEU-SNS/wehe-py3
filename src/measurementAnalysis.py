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
import glob
import math
import os.path

import pandas as pd
import numpy as np
import subprocess, json, pickle
from io import StringIO

from python_lib import *


def create_intervals_list(start, end, step):
    return [np.around([value, value + step], 3) for value in np.arange(start, end, step)]


def pcap_to_df(pcap_path, fields, pkt_filter=None):
    command = ['tshark', '-r', pcap_path, '-T', 'fields', '-E', 'header=y', '-E', 'separator=,', '-E', 'quote=d']
    for f in fields: command += ['-e', f]
    if pkt_filter: command += ['-Y', pkt_filter]

    p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, err = p.communicate()

    return pd.read_csv(StringIO(output.decode('utf-8')))


class Performance:
    def __init__(self, pkts_df, start_t, end_t, perf_func):
        self.pkts_df = pkts_df
        self.pkts_df.index = self.pkts_df['timestamp']

        self.start_t = start_t
        self.end_t = end_t
        self.perf_func = perf_func

    def compute_perfs(self, interval_size):
        intervals, perfs = create_intervals_list(self.start_t, self.end_t, interval_size), []
        for interval in intervals:
            perfs.append((interval[1], self.perf_func(self.pkts_df, interval)))
        return pd.DataFrame(perfs, columns=['interval', 'perf'])

    def compute_total_perf(self):
        return self.perf_func(self.pkts_df, [self.start_t, self.end_t])


class RetransmissionPerf(Performance):
    def __init__(self, pkts_df, start_t, end_t):
        super().__init__(pkts_df, start_t, end_t, RetransmissionPerf.compute_retransmission_ratio)

    @staticmethod
    def compute_retransmission_ratio(pkts_df, interval):
        df = pkts_df[interval[0]:interval[1]]
        if df.shape[0] == 0:
            return -1
        return df[df['is_retransmitted']]['pkt_len'].sum() / df['pkt_len'].sum()


class LossPerf(Performance):
    def __init__(self, pkts_df, start_t, end_t):
        super().__init__(pkts_df, start_t, end_t, LossPerf.compute_loss_ratio)

    @staticmethod
    def compute_loss_ratio(pkts_df, interval):
        df = pkts_df[interval[0]:interval[1]]
        if df.shape[0] == 0:
            return -1
        return df[df['is_lost']]['pkt_len'].sum() / df['pkt_len'].sum()


class ThroughputPerf(Performance):
    def __init__(self, pkts_df, start_t, end_t):
        super().__init__(pkts_df, start_t, end_t, ThroughputPerf.compute_xput)

    @staticmethod
    def compute_xput(pkts_df, interval):
        df = pkts_df[interval[0]:interval[1]]
        if df.shape[0] == 0:
            return -1
        return round((df['pkt_len'].sum()) / (interval[1] - interval[0]) * 8e-6, 3)


class PathPairPerf:
    def __init__(self, paths_perf, filter_f=(lambda x: x)):
        self.paths_perf = paths_perf
        self.filter_f = filter_f

    def compute_perfs(self, interval_size):
        perfs = [perf.compute_perfs(interval_size).replace(-1, math.nan).dropna() for perf in self.paths_perf]
        return self.filter_f(pd.merge(perfs[0], perfs[1], how='inner', on=['interval'], suffixes=('_p1', '_p2')))


def get_iRTT_from_pcap(pcap_file, server_port):
    fields = {'tcp.analysis.initial_rtt': 'iRTT'}
    pkt_filter = "tcp.srcport=={}".format(server_port)
    return pcap_to_df(pcap_file, fields.keys(), pkt_filter=pkt_filter).rename(columns=fields).iRTT.iloc[0]


def get_lossEvents_from_pcap(pcap_file, server_port):
    # get the pkts sent by the server
    fields = {
        'frame.time_relative': 'time', 'tcp.seq': 'seq', 'tcp.len': 'length',
        'tcp.srcport': 'srcport', 'tcp.dstport': 'dstport',
        'tcp.analysis.out_of_order': 'is_out_of_order', 'tcp.analysis.retransmission': 'is_retransmission',
    }
    pkt_filter = "tcp.srcport=={}".format(server_port)
    pkts_df = pcap_to_df(pcap_file, fields.keys(), pkt_filter=pkt_filter).rename(columns=fields)

    # find packets that were lost
    retransmitted_pkts = pkts_df[
        (pkts_df.is_retransmission == 1) | (pkts_df.is_out_of_order == 1)
        ].drop_duplicates(subset='seq', keep="last")
    pkts_df['is_lost'] = pkts_df['seq'].isin(retransmitted_pkts.seq.values)
    pkts_df.loc[retransmitted_pkts.index, ['is_lost']] = False

    return pd.DataFrame({'timestamp': pkts_df.time, 'pkt_len': pkts_df.length, 'is_lost': pkts_df.is_lost})


def get_lossRatios_from_pcap(pcap_file, server_port, interval_size):
    loss_df = get_lossEvents_from_pcap(pcap_file, server_port)
    return LossPerf(loss_df, 0, loss_df.time.iloc[-1]).compute_perfs(interval_size)


def load_client_xputs(userID, historyCount, testID, resultsFolder):
    xputFile = '{}/{}/clientXputs/Xput_{}_{}_{}.json'.format(
        resultsFolder, userID, userID, historyCount, testID)

    if not os.path.exists(xputFile):
        return None

    with open(xputFile, 'r') as readFile:
        return json.load(readFile)


def load_replayInfo(userID, historyCount, testID, resultsFolder):
    replayInfoFile = '{}/{}/replayInfo/replayInfo_{}_{}_{}.json'.format(
        resultsFolder, userID, userID, historyCount, testID)

    if not os.path.exists(replayInfoFile):
        return None

    with open(replayInfoFile, 'r') as readFile:
        return json.load(readFile)


def get_pcap_filename(userID, historyCount, testID, resultsFolder):
    tcpdumpsResults_dir = os.path.join(resultsFolder, userID, 'tcpdumpsResults')
    regex_pcap = "*_{}_*_{}_{}*".format(userID, historyCount, testID)
    try:
        return glob.glob('{}/{}'.format(tcpdumpsResults_dir, regex_pcap))[0]
    except:
        return None


def get_measurements(measurementType, userID, historyCount, testID, kwargs, resultsFolder):
    # first client based measurements
    if measurementType == 'clientXputs':
        xputs = load_client_xputs(userID, historyCount, testID, resultsFolder)
        return {'type': measurementType, 'resultType': str(type(xputs)), 'result': xputs}

    # second measurements based on pcap files
    pcap_file = get_pcap_filename(userID, historyCount, testID, resultsFolder)
    if pcap_file is None:
        raise FileNotFoundError

    if measurementType == 'initialRTT':
        result = get_iRTT_from_pcap(pcap_file, kwargs['serverPort'])
        return {'type': measurementType, 'resultType': str(type(result)), 'result': result}

    if measurementType == 'lossEvents':
        loss_df = get_lossEvents_from_pcap(pcap_file, kwargs['serverPort'])
        result = {'columns': loss_df.columns.tolist(), 'data': loss_df.values.tolist()}
        return {'type': measurementType, 'resultType': str(type(loss_df)), 'result': result}

    if measurementType == 'lossRatios':
        perf_df = get_lossRatios_from_pcap(pcap_file, kwargs['serverPort'], kwargs['intervalSize'])
        result = {'columns': perf_df.columns.tolist(), 'data': perf_df.values.tolist()}
        return {'type': measurementType, 'resultType': str(type(perf_df)), 'result': result}

    return None


class GetMeasurementsAnalyzerRequestHandler(AnalyzerRequestHandler):

    @staticmethod
    def getCommandStr(): return "getMeasurements"

    @staticmethod
    def handleRequest(args):
        # parse args
        try:
            userID = args['userID'][0].decode('ascii', 'ignore')
            historyCount = int(args['historyCount'][0].decode('ascii', 'ignore'))
            testID = int(args['testID'][0].decode('ascii', 'ignore'))
            measurementType = args['measurementType'][0].decode('ascii', 'ignore')
            kwargs = json.loads(args['kwargs'][0].decode('ascii', 'ignore'))
        except Exception as e:
            return json.dumps({'success': False, 'missing': str(e)})

        # compute and return measurement
        try:
            resultsFolder = getCurrentResultsFolder()
            measurements = get_measurements(measurementType, userID, historyCount, testID, kwargs, resultsFolder)
        except Exception as e:
            return json.dumps({'success': False, 'error': str(e)})

        return json.dumps({'success': True, 'measurements': measurements}, cls=myJsonEncoder)




