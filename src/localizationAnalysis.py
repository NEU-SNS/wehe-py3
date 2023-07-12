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
import json

import gevent, gevent.pool, gevent.queue
import scipy

from multiprocessing.pool import ThreadPool


from python_lib import *
from measurementAnalysis import *

sys.path.append('testHypothesis')
import testHypothesis as TH

elogger = logging.getLogger('errorLogger')
loc_logger = logging.getLogger('localization_analysis')


# This part implements helper method to exchange measurement between servers
def cast_GETResult_object(value, type):
    if str(type) == str(pd.DataFrame):
        return pd.DataFrame(value['data'], columns=value['columns'])
    return value


def send_GETMeasurement_request(serverIP, args):
    analyzer_port = Configs().get('analyzer_tls_port')
    url = 'https://{}:{}/Results'.format(serverIP, analyzer_port)
    cert_file = '{}/ca.crt'.format(Configs().get('certs_folder'))

    response = requests.get(url=url, params=args, verify=cert_file).json()

    if response['success']:
        measurements = response['measurements']
        return cast_GETResult_object(measurements['result'], measurements['resultType'])
    return None


def execute_methods_in_parallel(funcs):
    pool = ThreadPool(processes=len(funcs))
    async_results = [pool.apply_async(func=f['cls'], kwds=f['kwargs']) for f in funcs]
    return [async_result.get() for async_result in async_results]


# Next part implements the statistical tests for localization
def compute_xput_stats(xputs):
    return max(xputs), min(xputs), np.average(xputs), np.median(xputs), np.std(xputs)


def get_interval_sizes(min_rtt, duration, mult_start=30, mult_end=50, min_nb_intervals=30):
    interval_sizes = []
    for i in np.arange(mult_start, mult_end + 1, 1):
        if (duration / (min_rtt * i)) >= min_nb_intervals:
            interval_sizes.append(round(min_rtt * i, 3))
    return interval_sizes


def compute_perf_correlation(pair_perf, interval_size):
    loss_ratios = pair_perf.compute_perfs(interval_size)
    statistic, pvalue = scipy.stats.spearmanr(loss_ratios.perf_p1, loss_ratios.perf_p2, alternative='greater')
    return {'intervalSize': interval_size, 'corrVal': statistic, 'corrPVal': pvalue}


def detect_per_service_policing(userID, historyCount, testID, secondServerIP, resultsFolder, server_port_mappings):
    pcap_path = get_pcap_filename(userID, historyCount, testID, resultsFolder)
    replayInfo = load_replayInfo(userID, historyCount, testID, resultsFolder)

    if (replayInfo is None) or (pcap_path is None):
        elogger.error('FAILED localization test for {} {}: result files missing'.format(userID, historyCount))
        return None

    server_port = server_port_mappings[replayInfo[4].replace('-', '_')]

    # step 1: measurement collection: the initial RTT + loss events
    # initial RTT
    command_args = {'command': 'getMeasurements', 'userID': userID, 'historyCount': historyCount, 'testID': testID,
                    'measurementType': 'initialRTT', 'kwargs': json.dumps({'serverPort': server_port})}
    remote_f = {'cls': send_GETMeasurement_request, 'kwargs': {'serverIP': secondServerIP, 'args': command_args}}
    local_f = {'cls': get_iRTT_from_pcap, 'kwargs': {'pcap_file': pcap_path, 'server_port': server_port}}
    iRTTs = execute_methods_in_parallel([local_f, remote_f])

    # loss events
    command_args = {'command': 'getMeasurements', 'userID': userID, 'historyCount': historyCount, 'testID': testID,
                    'measurementType': 'lossEvents', 'kwargs': json.dumps({'serverPort': server_port})}
    remote_f = {'cls': send_GETMeasurement_request, 'kwargs': {'serverIP': secondServerIP, 'args': command_args}}
    local_f = {'cls': get_lossEvents_from_pcap, 'kwargs': {'pcap_file': pcap_path, 'server_port': server_port}}
    loss_dfs = execute_methods_in_parallel([local_f, remote_f])

    # check all remote calls are successful so far
    if (None in iRTTs) or (np.any([loss_df is None for loss_df in loss_dfs])):
        elogger.error('FAILED localization test for {} {}: collecting measurements'.format(userID, historyCount))
        return None

    # step 2: compute the interval sizes (multiples of iRTT)
    min_rtt = min(iRTTs)
    duration = min([loss_df.timestamp.iloc[-1] for loss_df in loss_dfs])
    interval_sizes = get_interval_sizes(min_rtt, duration)

    if len(interval_sizes) == 0:
        elogger.error('FAILED localization test for {} {}: not enough measurements'.format(userID, historyCount))
        return None

    # step 3: for each interval size: compute loss ratios + apply spearman corr ratio
    loss_perfs = [LossPerf(pkts_df, 0, duration) for pkts_df in loss_dfs]
    loss_pair_perf = PathPairPerf(
        loss_perfs, filter_f=(lambda perfs: perfs[(perfs.perf_p1 > 0) | (perfs.perf_p2 > 0)])
    )

    corr_funcs = []
    for interval_size in interval_sizes:
        corr_funcs.append({'cls': compute_perf_correlation,
                           'kwargs': {'pair_perf': loss_pair_perf, 'interval_size': interval_size}})
    corr_results = execute_methods_in_parallel(corr_funcs)

    results_as_dict = {
        'simReplay1AvgLoss': loss_perfs[0].compute_total_perf(),
        'simReplay2AvgLoss': loss_perfs[1].compute_total_perf(),
        'spearmanCorrStats': corr_results
    }
    return results_as_dict


def detect_per_service_plan_throttling(userID, historyCount, testID, secondServerIP, resultsFolder, alpha):
    # step 1: measurement collection: client side xputs
    command_args = {'command': 'getMeasurements', 'userID': userID, 'historyCount': historyCount, 'testID': testID,
                    'measurementType': 'clientXputs', 'kwargs': json.dumps({})}
    remote_f = {'cls': send_GETMeasurement_request, 'kwargs': {'serverIP': secondServerIP, 'args': command_args}}
    local_f = {'cls': load_client_xputs,
               'kwargs': {'userID': userID, 'historyCount': historyCount, 'testID': testID, 'resultsFolder': resultsFolder}}
    xputs = execute_methods_in_parallel([local_f, remote_f])

    # check all remote calls are successful so far
    if None in xputs:
        elogger.error('FAILED localization test for {} {}: collecting measurements'.format(userID, historyCount))
        return None

    # step 2: sum the simultaneous replay throughput
    xputs_s1, dur_s1 = xputs[0]
    (xputMax1, xputMin1, xputAvg1, xputMed1, xputStd1) = compute_xput_stats(xputs_s1)

    xputs_s2, dur_s2 = xputs[1]
    (xputMax2, xputMin2, xputAvg2, xputMed2, xputStd2) = compute_xput_stats(xputs_s2)

    sim_xputs_sum = [sum(x) for x in zip(xputs_s1, xputs_s2)]

    # step 3: get single replay xput
    # TODO: implement retrieve client xputs for the single replay test
    single_test_xputs = sim_xputs_sum
    results = TH.doTests(sim_xputs_sum, single_test_xputs, alpha)

    # step 3: test if the throughput sum have the same distribution as the single replay xput
    (xputMaxS, xputMinS, xputAvgS, xputMedS, xputStdS) = compute_xput_stats(single_test_xputs)
    results_as_dict = {
        'avgXputDiffPct': results[0], 'KSAcceptRatio': results[1], 'avgXputDiff': results[2],
        'simReplay1XputStats': {'max': xputMax1, 'min': xputMin1, 'average': xputAvg1, 'median': xputMed1, 'std': xputStd1},
        'simReplay2XputStats': {'max': xputMax2, 'min': xputMin2, 'average': xputAvg2, 'median': xputMed2, 'std': xputStd2},
        'singleReplayXputStats': {'max': xputMaxS, 'min': xputMinS, 'average': xputAvgS, 'median': xputMedS, 'std': xputStdS},
        "KSAvgDVal": results[7], "KSAvgPVal": results[8], "KSDVal": results[9], "KSPVal": results[10]
    }
    return results_as_dict


class LocalizationAnalysis:

    def __init__(self):
        # TODO: add the configuration
        self.min_nb_intervals = 30
        self.false_positive_rate = 0.05
        self.alpha = 0.95

        self.server_port_mappings = {}
        self.loc_queue = gevent.queue.Queue()

    def add_job(self, userID, historyCount, testID, serverIP):
        self.loc_queue.put((userID, historyCount, testID, serverIP))

    def loc_queue_processor(self, q):
        pool = gevent.pool.Pool()
        while True:
            userID, historyCount, testID, serverIP = q.get()
            pool.apply_async(self.localizer, args=(userID, historyCount, testID, serverIP))

    def run(self):
        self.server_port_mappings = loadReplaysServerPortMapping()

        loc_thread = gevent.Greenlet.spawn(self.loc_queue_processor, self.loc_queue)
        loc_thread.start()

    def localizer(self, userID, historyCount, testID, secondServerIP):
        resultsFolder = getCurrentResultsFolder()
        LOG_ACTION(logger, 'localizer: {}, {}, {}'.format(userID, historyCount, testID))

        localize_results = []
        result_file = '{}/{}/localizeDecisions/localizeResults_{}_{}_{}.json'.format(
            getCurrentResultsFolder(), userID, userID, historyCount, testID)

        # localizer will try to test for different differentiation method
        # first per service plan throttling (i.e., ISP handle every plan traffic in dedicated queue)
        results1 = detect_per_service_plan_throttling(
            userID, historyCount, testID, secondServerIP, resultsFolder, self.alpha)
        localize_results.append({
            'localizationTestType': 'per_service_plan_throttling', 'statistics': results1
        })

        # second per service aggregate policing (i.e., ISP handle all traffic of same service in same shallow queue)
        results2 = detect_per_service_policing(
            userID, historyCount, testID, secondServerIP, resultsFolder, self.server_port_mappings)
        localize_results.append({
            'localizationTestType': 'per_service_policing', 'statistics': results2
        })

        with open(result_file, "w") as writeFile:
            json.dump(localize_results, writeFile)

        return localize_results


locAnalyzer = LocalizationAnalysis()


class PostLocalizeRequestHandler(AnalyzerRequestHandler):

    @staticmethod
    def getCommandStr():
        return "localize"

    @staticmethod
    def handleRequest(args):
        try:
            userID = args['userID'][0].decode('ascii', 'ignore')
            historyCount = int(args['historyCount'][0].decode('ascii', 'ignore'))
            testID = int(args['testID'][0].decode('ascii', 'ignore'))
            serverIP = args['serverIP'][0].decode('ascii', 'ignore')
        except KeyError as e:
            return json.dumps({'success': False, 'missing': str(e)})
        except ValueError as e:
            return json.dumps({'success:': False, 'value error:': str(e)})

        locAnalyzer.add_job(userID, historyCount, testID, serverIP)
        LOG_ACTION(logger, 'New localize job added to queue'.format(userID, historyCount, testID, serverIP))

        return json.dumps({'success': True})


class GETLocalizeResultRequestHandler(AnalyzerRequestHandler):

    @staticmethod
    def getCommandStr():
        return "localizeResult"

    @staticmethod
    def handleRequest(args):
        try:
            userID = args['userID'][0].decode('ascii', 'ignore')
            historyCount = int(args['historyCount'][0].decode('ascii', 'ignore'))
            testID = int(args['testID'][0].decode('ascii', 'ignore'))
        except KeyError as e:
            return json.dumps({'success': False, 'missing': str(e)})
        except ValueError as e:
            return json.dumps({'success:': False, 'value error:': str(e)})

        result_file = '{}/{}/localizeDecisions/localizeResults_{}_{}_{}.json'.format(
            getCurrentResultsFolder(), userID, userID, historyCount, testID)

        with open(result_file, "r") as json_file:
            result = json.load(json_file)

        return json.dumps({'success': True, 'response': result}, cls=myJsonEncoder)


if __name__ == "__main__":
    Configs().set('certs_folder', './ssl/')
    Configs().set('analyzer_tls_port', 56566)
    Configs().set('replay_parent_folder', '/Users/shmeis/Desktop/PHD/Research/code/wehe-py3/replayTraces/')
    Configs().set('resultsFolder', '/Users/shmeis/Desktop/PHD/Research/code/wehe-py3/var/spool/wehe/replay/')

    userID, historyCount, testID = '@49be17rg3', 19, 0
    # print(get_pcap_filename(userID, historyCount, testID, getCurrentResultsFolder()))
    s2_ip = '34.28.122.46'
    # localizer = LocalizationAnalysis()
    # localizer.run()
    print('start test2')
    # print(localizer.localizer(userID, historyCount, testID, s2_ip))
    # x1, x2, x3 = detect_per_service_plan_throttling(userID, historyCount, testID, s2_ip, getCurrentResultsFolder(), 0.05)
    # print(x1[1:10], x2[1:10], x3[1:10])

    # df = pd.read_csv('/Users/shmeis/Desktop/df_1.csv')
    # df.set_index('timestamp', inplace=True)
    # print(df[0:1])

    args = {'userID': [userID.encode('ascii', 'ignore')],
            'historyCount': [str(historyCount).encode('ascii', 'ignore')],
            'testID': [str(testID).encode('ascii', 'ignore')]}
    print(GETLocalizeResultRequestHandler.handleRequest(args))
