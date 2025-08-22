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
import os.path

import pandas as pd
import numpy as np
from io import StringIO

from python_lib import *


MIN_NB_PACKETS = 10


def create_intervals_list(start, end, step):
    return [np.around([value, value + step], 3) for value in np.arange(start, end, step)]


def pcap_to_df(pcap_path, fields, pkt_filter=None):
    command = ['tshark', '-r', pcap_path, '-T', 'fields', '-E', 'header=y', '-E', 'separator=,', '-E', 'quote=d']
    for f in fields: command += ['-e', f]
    if pkt_filter: command += ['-Y', pkt_filter]
    
    try: 
        p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, err = p.communicate()
    except Exception as e:
        return pd.DataFrame(columns=fields)
      
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
        if df.shape[0] <= MIN_NB_PACKETS:
            return -1
        return df[df['is_retransmitted']]['pkt_len'].sum() / df['pkt_len'].sum()


class LossPerf(Performance):
    def __init__(self, pkts_df, start_t, end_t):
        super().__init__(pkts_df, start_t, end_t, LossPerf.compute_loss_ratio)

    @staticmethod
    def compute_loss_ratio(pkts_df, interval):
        df = pkts_df[interval[0]:interval[1]]
        if df.shape[0] <= MIN_NB_PACKETS:
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


def get_pcap_filename(userID, historyCount, testID, resultsFolder):
    tcpdumpsResults_dir = os.path.join(resultsFolder, userID, 'tcpdumpsResults')
    regex_pcap = "*_{}_*_{}_{}*".format(userID, historyCount, testID)
    for _ in np.arange(3):
        pcap_files = glob.glob('{}/{}'.format(tcpdumpsResults_dir, regex_pcap))
        if pcap_files:
            return pcap_files[0]
        LOG_ACTION(logger, 'Can not find pcap file {}'.format(regex_pcap))
        time.sleep(1)
    return None


def get_minRttAndDuration_from_pcap(pcap_file, server_port):
    fields = {'frame.time_relative': 'time', 'tcp.analysis.ack_rtt': 'rtt'}
    pkt_filter = "tcp.dstport=={}".format(server_port)
    pkt_df = pcap_to_df(pcap_file, fields.keys(), pkt_filter=pkt_filter).rename(columns=fields)

    if pkt_df.empty:
        return None
    return {'minRtt': pkt_df.rtt.min(), 'duration': pkt_df.time.max()}


def compute_loss_vs_nonloss_sum(vals):
    total_sum, loss_sum = vals['length_x'].iat[0], vals['length_y'].sum()
    return loss_sum, total_sum - loss_sum


def get_lossEvents_from_pcap(pcap_file, server_port):
    # get the pkts sent by the server
    fields = {
        'frame.time_relative': 'time', 'tcp.seq': 'seq', 'tcp.len': 'length',
        'tcp.srcport': 'srcport', 'tcp.dstport': 'dstport',
        'tcp.analysis.out_of_order': 'is_out_of_order', 'tcp.analysis.retransmission': 'is_retransmission',
    }
    pkt_filter = "tcp.srcport=={}".format(server_port)
    pkts_df = pcap_to_df(pcap_file, fields.keys(), pkt_filter=pkt_filter).rename(columns=fields)

    pkts_df['is_lost'] = False
    pkts_df['next_seq'] = pkts_df['seq'] + pkts_df['length']

    # find retransmitted packets
    retransmitted_pkts = pkts_df[(pkts_df.is_retransmission == 1) | (pkts_df.is_out_of_order == 1)].drop_duplicates(
        subset='seq', keep="last")
    # if there are no retransmitted packets (or marked as retransmitted), return immediately
    if retransmitted_pkts.empty:
        return pd.DataFrame({'timestamp': pkts_df.time, 'pkt_len': pkts_df.length, 'is_lost': pkts_df.is_lost})

    try:
        # if the dataframe is too large, it will go out of memory
        lost_pkts = pd.merge(pkts_df, retransmitted_pkts, how='cross')
    except MemoryError:
        return pd.DataFrame({'timestamp': pkts_df.time, 'pkt_len': pkts_df.length, 'is_lost': pkts_df.is_lost})
    
    # find packets that were re-transmitted and compute non/lost bytes sum
    lost_pkts = lost_pkts[
        (lost_pkts['seq_y'] >= lost_pkts['seq_x']) &
        (lost_pkts['seq_y'] < lost_pkts['next_seq_x']) &
        (lost_pkts['time_x'] < lost_pkts['time_y'])]
    lost_pkts = lost_pkts.drop_duplicates(subset='time_y', keep="last")

    lost_pkts = lost_pkts.groupby(['time_x', 'seq_x']).apply(compute_loss_vs_nonloss_sum).reset_index(name='loss')
    lost_pkts[['loss_sum', 'nonloss_sum']] = lost_pkts['loss'].apply(pd.Series)

    labeled_sent_pkts = pd.concat([
        pd.DataFrame({'time': lost_pkts['time_x'], 'seq': lost_pkts['seq_x'], 'length': lost_pkts['loss_sum'], 'is_lost': True}),
        pd.DataFrame({'time': lost_pkts['time_x'], 'seq': lost_pkts['seq_x'], 'length': lost_pkts['nonloss_sum'],'is_lost': False})
    ])

    # label loss in the original sent_pkts dataframe
    pkts_df = pd.merge(pkts_df, labeled_sent_pkts, how='outer', on=['time', 'seq'])
    pkts_df['is_lost'] = pkts_df['is_lost_y'].fillna(False) & pkts_df['is_lost_y']
    pkts_df['length_y'] = pkts_df['length_y'].fillna(1e10)
    pkts_df['length'] = pkts_df[['length_x', 'length_y']].min(axis=1)

    return pd.DataFrame({'timestamp': pkts_df.time, 'pkt_len': pkts_df.length, 'is_lost': pkts_df.is_lost})


def get_lossRatios_from_pcap(pcap_file, server_port, interval_sizes):
    loss_df = get_lossEvents_from_pcap(pcap_file, server_port)
    loss_perf = LossPerf(loss_df, 0, loss_df.timestamp.iloc[-1])

    loss_ratios_df = []
    for interval_size in interval_sizes:
        loss_ratios = loss_perf.compute_perfs(interval_size).replace(-1, math.nan).dropna()
        loss_ratios['interval_size'] = interval_size
        loss_ratios_df.append(loss_ratios)
    return pd.concat(loss_ratios_df)


def load_client_xputs(userID, historyCount, testID, resultsFolder):
    xputFile = '{}/{}/clientXputs/Xput_{}_{}_{}.json'.format(
        resultsFolder, userID, userID, historyCount, testID)

    if not os.path.exists(xputFile):
        return None

    with open(xputFile, 'r') as readFile:
        return json.load(readFile)


def get_measurements(measurementType, userID, historyCount, testID, kwargs, resultsFolder):
    # first client based measurements
    if measurementType == 'clientXputs':
        xputs = load_client_xputs(userID, historyCount, testID, resultsFolder)
        return {'type': measurementType, 'resultType': str(type(xputs)), 'result': xputs}

    # second measurements based on pcap files
    pcap_file = get_pcap_filename(userID, historyCount, testID, resultsFolder)
    if pcap_file is None:
        raise FileNotFoundError

    if measurementType == 'minRttAndDuration':
        result = get_minRttAndDuration_from_pcap(pcap_file, kwargs['serverPort'])
        
        if result is None:
            raise ValueError("No packets found in pcap file") 

        return {'type': measurementType, 'resultType': str(type(result)), 'result': result}

    if measurementType == 'lossEvents':
        loss_df = get_lossEvents_from_pcap(pcap_file, kwargs['serverPort'])
        result = {'columns': loss_df.columns.tolist(), 'data': loss_df.values.tolist()}
        return {'type': measurementType, 'resultType': str(type(loss_df)), 'result': result}

    if measurementType == 'lossRatios':
        perf_df = get_lossRatios_from_pcap(pcap_file, kwargs['serverPort'], kwargs['intervalSizes'])
        result = {'columns': perf_df.columns.tolist(), 'data': perf_df.values.tolist()}
        return {'type': measurementType, 'resultType': str(type(perf_df)), 'result': result}

    return None


def load_replayInfo(userID, historyCount, testID, resultsFolder):
    replayInfoFile = '{}/{}/replayInfo/replayInfo_{}_{}_{}.json'.format(
        resultsFolder, userID, userID, historyCount, testID)

    if not os.path.exists(replayInfoFile):
        return None

    with open(replayInfoFile, 'r') as readFile:
        return json.load(readFile)


class GetMeasurementsRequestHandler(AnalyzerRequestHandler):

    @staticmethod
    def getCommandStr():
        return "getMeasurements"

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