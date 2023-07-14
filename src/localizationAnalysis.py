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


def send_GETMeasurement_request(serverIP, params):
    analyzer_port = Configs().get('analyzer_tls_port')
    url = 'https://{}:{}/Results'.format(serverIP, analyzer_port)
    cert_file = os.path.join(Configs().get('certs_folder'), 'ca.crt')

    response = requests.get(url=url, params=params, verify=cert_file).json()

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


# TODO: re-visit the range of interval size to look at [30RTT - 50RTT]
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


def detect_correlated_loss(userID, historyCount, testID, secondServerIP, resultsFolder, server_port_mappings):
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
    remote_f = {'cls': send_GETMeasurement_request, 'kwargs': {'serverIP': secondServerIP, 'params': command_args}}
    local_f = {'cls': get_iRTT_from_pcap, 'kwargs': {'pcap_file': pcap_path, 'server_port': server_port}}
    iRTTs = execute_methods_in_parallel([local_f, remote_f])

    # loss events
    command_args = {'command': 'getMeasurements', 'userID': userID, 'historyCount': historyCount, 'testID': testID,
                    'measurementType': 'lossEvents', 'kwargs': json.dumps({'serverPort': server_port})}
    remote_f = {'cls': send_GETMeasurement_request, 'kwargs': {'serverIP': secondServerIP, 'params': command_args}}
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
        'pairReplay1AvgLoss': loss_perfs[0].compute_total_perf(),
        'pairReplay2AvgLoss': loss_perfs[1].compute_total_perf(),
        'spearmanCorrStats': corr_results
    }
    return results_as_dict


def compare_pairsum_vs_single_replay_xput(userID, historyCount, testID, secondServerIP, resultsFolder, alpha):
    # step 1: measurement collection: client side xputs
    command_args = {'command': 'getMeasurements', 'userID': userID, 'historyCount': historyCount, 'testID': testID,
                    'measurementType': 'clientXputs', 'kwargs': json.dumps({})}
    remote_f = {'cls': send_GETMeasurement_request, 'kwargs': {'serverIP': secondServerIP, 'params': command_args}}
    local_f = {'cls': load_client_xputs,
               'kwargs': {'userID': userID, 'historyCount': historyCount, 'testID': testID, 'resultsFolder': resultsFolder}}
    xputs = execute_methods_in_parallel([local_f, remote_f])

    # check all remote calls are successful so far
    if None in xputs:
        elogger.error('FAILED localization test for {} {}: collecting measurements'.format(userID, historyCount))
        return None

    # step 2: sum the simultaneous replay throughput
    xputs_s1, dur_s1 = xputs[0]
    xputs_s2, dur_s2 = xputs[1]
    pair_xput_sum = [sum(x) for x in zip(xputs_s1, xputs_s2)]

    # step 3: get single replay xput
    # TODO: implement retrieve client xputs for the single replay test
    single_test_xputs = pair_xput_sum

    # TODO: revisit the statistical test to check if two samples come from same distribution (KS does not apply here)
    results = TH.doTests(pair_xput_sum, single_test_xputs, alpha)

    # step 3: test if the throughput sum have the same distribution as the single replay xput
    xput_stats_keys = ['max', 'min', 'average', 'median', 'std']
    results_as_dict = {
        'avgXputDiffPct': results[0], 'KSAcceptRatio': results[1], 'avgXputDiff': results[2],
        'pairReplay1XputStats': {k: v for k, v in zip(xput_stats_keys, compute_xput_stats(xputs_s1))},
        'pairReplay2XputStats': {k: v for k, v in zip(xput_stats_keys, compute_xput_stats(xputs_s2))},
        'pairReplaySumXputStats': {k: v for k, v in zip(xput_stats_keys, compute_xput_stats(pair_xput_sum))},
        'singleReplayXputStats': {k: v for k, v in zip(xput_stats_keys, compute_xput_stats(single_test_xputs))},
        "KSAvgDVal": results[7], "KSAvgPVal": results[8], "KSDVal": results[9], "KSPVal": results[10]
    }
    return results_as_dict


def localize(userID, historyCount, testID, secondServerIP, resultsFolder, params):
    LOG_ACTION(logger, 'Run localization test: {}, {}, {}'.format(userID, historyCount, testID))

    localize_results = []
    loc_decisions_dir = os.path.join(resultsFolder, userID, 'localizeDecisions')
    os.makedirs(loc_decisions_dir, exist_ok=True)
    result_file = '{}/localizeResults_{}_{}_{}.json'.format(loc_decisions_dir, userID, historyCount, testID)

    # localize will try to test for different differentiation method
    # first per service plan throttling (i.e., ISP handle every plan traffic in dedicated queue)
    results1 = compare_pairsum_vs_single_replay_xput(
        userID, historyCount, testID, secondServerIP, resultsFolder, params['alpha'])
    localize_results.append({'localizationTestType': 'pairsum_vs_single_xput', 'statistics': results1})

    # second per service aggregate policing (i.e., ISP handle all traffic of same service in same shallow queue)
    results2 = detect_correlated_loss(
        userID, historyCount, testID, secondServerIP, resultsFolder, params['server_port_mappings'])
    localize_results.append({'localizationTestType': 'loss_correlation', 'statistics': results2})

    with open(result_file, "w") as writeFile:
        json.dump(localize_results, writeFile)

    return localize_results


LOC_Queue = gevent.queue.Queue()


def runLocalizationTestsProcessor():
    LOG_ACTION(logger, 'Ready to processes localization tests request')
    params = {'server_port_mappings': loadReplaysServerPortMapping(), 'min_nb_intervals': 30, 'alpha': 0.95}

    pool = gevent.pool.Pool()
    while True:
        userID, historyCount, testID, secondServerIP = LOC_Queue.get()
        results_folder = getCurrentResultsFolder()
        pool.apply_async(localize, args=(userID, historyCount, testID, secondServerIP, results_folder, params))


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
            secondServerIP = args['secondServerIP'][0].decode('ascii', 'ignore')
        except KeyError as e:
            return json.dumps({'success': False, 'missing': str(e)})
        except ValueError as e:
            return json.dumps({'success:': False, 'value error:': str(e)})

        LOC_Queue.put((userID, historyCount, testID, secondServerIP))
        LOG_ACTION(logger, 'New localize job added to queue'.format(userID, historyCount, testID, secondServerIP))

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

        result_folder = getCurrentResultsFolder()
        result_file = '{}/{}/localizeDecisions/localizeResults_{}_{}_{}.json'.format(
            result_folder, userID, userID, historyCount, testID)

        # check if results are ready
        if not os.path.isfile(result_file):
            LOG_ACTION(logger, 'result not ready yet, adding localize job to queue :{}, {}, {}'.format(
                userID, historyCount, testID
            ))
            return json.dumps({'success': False, 'error': 'No result found'})

        replayInfo = load_replayInfo(userID, historyCount, testID, result_folder)
        with open(result_file, "r") as json_file:
            results = json.load(json_file)

        locTests = {t['localizationTestType']: t['statistics'] for t in results if t['statistics']}
        response = {
            'userID': userID, 'historyCount': str(historyCount), 'testID': str(testID),
            'timestamp': replayInfo[0], 'replayName': replayInfo[4], 'localization_tests': list(locTests.keys())
        }

        if 'pairsum_vs_single_xput' in locTests.keys():
            stats = locTests['pairsum_vs_single_xput']
            response['pairsum_vs_single_xput'] = {
                'area_test': stats['avgXputDiffPct'], 'ks2_ratio_test': stats['KSAcceptRatio'],
                'xput_avg_pairsum': stats['pairReplaySumXputStats']['average'],
                'xput_avg_single': stats['singleReplayXputStats']['average'],
                'ks2dVal': stats['KSDVal'], 'ks2pVal': stats['KSPVal']
            }

        if 'loss_correlation' in locTests.keys():
            stats = locTests['loss_correlation']
            response['loss_correlation'] = {
                'interval_sizes': [s['intervalSize'] for s in stats['spearmanCorrStats']],
                'corr_pvalues': [s['corrPVal'] for s in stats['spearmanCorrStats']],
                'pair_replay1_avg_loss': stats['pairReplay1AvgLoss'], 'pair_replay2_avg_loss': stats['pairReplay2AvgLoss']
            }
        return json.dumps({'success': True, 'response': response}, cls=myJsonEncoder)

