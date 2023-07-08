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
import gevent
import scipy

from python_lib import *
from measurementAnalysis import *


def castGETResultObject(value, type):
    if str(type) == str(pd.DataFrame):
        return pd.DataFrame(value['data'], columns=value['columns'])
    return value


def sendGETMeasurementRequest(serverIP, args):
    analyzer_port = Configs().get('analyzer_tls_port')
    url = 'https://{}:{}/Results'.format(serverIP, analyzer_port)
    cert_file = '{}/ca.crt'.format(Configs().get('certs_folder'))

    response = requests.get(url=url, params=args, verify=cert_file).json()

    if response['success']:
        measurements = response['measurements']
        return castGETResultObject(measurements['result'], measurements['resultType'])
    return None


def load_replayInfo(userID, historyCount, testID):
    replayInfoFile = '{}/{}/replayInfo/replayInfo_{}_{}_{}.json'.format(
        getCurrentResultsFolder(), userID, userID, historyCount, testID)

    if not os.path.exists(replayInfoFile):
        return None

    with open(replayInfoFile, 'r') as readFile:
        return json.load(readFile)


def execute_methods_in_parallel(funcs):
    gs = [gevent.Greenlet.spawn(f['cls'], **f['kwargs']) for f in funcs]
    for g in gs:
        g.join()
    return [g.value for g in gs]


MIN_NB_INTERVALS = 30


def get_interval_sizes(min_rtt, duration, mult_start=10, mult_end=50):
    sints = []
    for i in np.arange(mult_start, mult_end+1, 1):
        if (duration/(min_rtt*i)) >= MIN_NB_INTERVALS:
            sints.append(round(min_rtt * i, 3))
    return sints


class LocalizationAnalysis:

    def __init__(self):
        self.server_port_mappings = loadReplaysServerPortMapping()

    def runLocalizationTest(self, userID, historyCount, testID, secondServerIP):
        results_folder = getCurrentResultsFolder()

        replayInfo = load_replayInfo(userID, historyCount, testID)
        if not replayInfo:
            return None

        replay_name = replayInfo[4]
        server_port = self.server_port_mappings[replay_name.replace('-', '_')]
        pcap_filename = 'dump_server_{}_{}_{}_{}_{}_out.pcap'.format(
            userID, replay_name, replayInfo[5], historyCount, testID)
        pcap_path = '{}/{}/tcpdumpsResults/{}'.format(results_folder, userID, pcap_filename)

        # step 1: get the initial RTT from both servers
        command_args = {'command': 'getMeasurements', 'userID': userID, 'historyCount': historyCount, 'testID': testID,
                        'measurementType': 'initialRTT',
                        'kwargs': json.dumps({'serverPort': server_port, 'pcapFilename': pcap_filename})}
        remote_f = {'cls': sendGETMeasurementRequest, 'kwargs': {'serverIP': secondServerIP, 'args': command_args}}
        local_f = {'cls': get_iRTT_from_pcap, 'kwargs': {'pcap_file': pcap_path, 'server_port': server_port}}
        iRTTs = execute_methods_in_parallel([local_f, remote_f])

        # step 2: get loss events from both servers
        command_args = {'command': 'getMeasurements', 'userID': userID, 'historyCount': historyCount, 'testID': testID,
                        'measurementType': 'lossEvents',
                        'kwargs': json.dumps({'serverPort': server_port, 'pcapFilename': pcap_filename})}
        remote_f = {'cls': sendGETMeasurementRequest, 'kwargs': {'serverIP': secondServerIP, 'args': command_args}}
        local_f = {'cls': get_lossEvents_from_pcap, 'kwargs': {'pcap_file': pcap_path, 'server_port': server_port}}
        loss_dfs = execute_methods_in_parallel([local_f, remote_f])

        for i, df in enumerate(loss_dfs):
            df.to_csv('~/Desktop/df_{}.csv'.format(i))

        # check all remote calls are successful so far
        if (None in iRTTs) or (np.any([loss_df is None for loss_df in loss_dfs])):
            print('data missing')
            return None

        # step 3: compute the interval sizes (multiples of iRTT)
        min_rtt = min(iRTTs)
        duration = min([loss_df.timestamp.iloc[-1] for loss_df in loss_dfs])
        sints = get_interval_sizes(min_rtt, duration)
        print(min_rtt, duration, sints)

        # step 4: compute loss ratios based on interval sizes + apply spearman corr ratio
        loss_pair_perf = PathPairPerf(
            [LossPerf(pkts_df, 0, duration) for pkts_df in loss_dfs],
            filter_f=(lambda perfs: perfs[(perfs.perf_p1 > 0) | (perfs.perf_p2 > 0)])
        )
        corr_results = []
        for sint in sints:
            loss_ratios = loss_pair_perf.compute_perfs(sint)
            statistic, pvalue = scipy.stats.spearmanr(loss_ratios.perf_p1, loss_ratios.perf_p2, alternative='greater')
            corr_results.append({'interval_size': sint, 'statistics': statistic, 'pvalue': pvalue})

        return pd.DataFrame(corr_results)


if __name__ == "__main__":
    Configs().set('certs_folder', './ssl/')
    Configs().set('analyzer_tls_port', 56566)
    Configs().set('replay_parent_folder', '/Users/shmeis/Desktop/PHD/Research/code/wehe-py3/replayTraces/')
    Configs().set('resultsFolder', '/Users/shmeis/Desktop/PHD/Research/code/wehe-py3/var/spool/wehe/replay/')

    userID, historyCount, testID = '@49be17rg3', 19, 0
    s2_ip = '34.28.122.46'
    localizer = LocalizationAnalysis()
    print('start test2')
    print(localizer.runLocalizationTest(userID, historyCount, testID, s2_ip))
