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

import scipy, requests, pickle
from multiprocessing.pool import ThreadPool
from scipy.stats import mannwhitneyu

from python_lib import *
from measurementAnalysis import *
import weheResultsWriter as bqResultWriter

elogger = logging.getLogger('errorLogger')
logger = logging.getLogger('replay_analyzer')


# This part implements helper method to exchange measurement between servers
def cast_GETResult_object(value, type):
    if str(type) == str(pd.DataFrame):
        return pd.DataFrame(value['data'], columns=value['columns'])
    return value



def send_GETMeasurement_request(serverIP, params, *, port=None, cert_file=None, session=None):
    analyzer_port = port or Configs().get('analyzer_tls_port')
    cert_file = cert_file or os.path.join(Configs().get('certs_folder'), 'ca.crt')
    session = session or requests
    url = 'https://{}:{}/Results'.format(serverIP, analyzer_port)
    try:
        response = json.loads(session.get(url=url, params=params, verify=cert_file).text)
    except Exception as e:
        elogger.error("GETMeasurement failed for serverIP {}, error: {}".format(serverIP, e))
        return None

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


# TODO: re-visit the range of interval size to look at [10RTT - 50RTT]
def get_interval_sizes(min_rtt, duration, mult_start=10, mult_end=50, min_nb_intervals=30):
    interval_sizes = []
    for i in np.arange(mult_start, mult_end + 1, 1):
        if (duration / (min_rtt * i)) >= min_nb_intervals:
            interval_sizes.append(round(min_rtt * i, 3))
    return interval_sizes


def concat_non_lossy_intervals(perf):
    perf['index'], perf['lossy'] = perf.index.values, (perf.perf_p1 > 0) | (perf.perf_p2 > 0)
    lossy_df, non_lossy_df = perf[perf['lossy']].copy(), perf[~perf['lossy']].copy()

    non_lossy_df['index_diff'] = non_lossy_df['index'].diff().replace(math.nan, 2)
    non_lossy_df = non_lossy_df[non_lossy_df['index_diff'] > 1].copy()

    perf = pd.concat([non_lossy_df, lossy_df]).sort_values(by='interval')
    return perf.reset_index(drop=True).drop(columns=['index_diff', 'index', 'lossy'])


def compute_perf_correlation(pair_perf_dfs, interval_size):
    df1, df2 = pair_perf_dfs[0], pair_perf_dfs[1]
    loss_ratios = concat_non_lossy_intervals(pd.merge(
        df1[df1['interval_size'] == interval_size], df2[df2['interval_size'] == interval_size],
        how='inner', on=['interval', 'interval_size'], suffixes=('_p1', '_p2')
    ))

    if loss_ratios.empty:
        return {'intervalSize': interval_size, 'corrVal': np.nan, 'corrPVal': np.nan}

    statistic, pvalue = scipy.stats.spearmanr(loss_ratios.perf_p1, loss_ratios.perf_p2, alternative='greater')
    return {'intervalSize': interval_size, 'corrVal': statistic, 'corrPVal': pvalue}


def detect_correlated_loss(userID, testID, simServers_info, resultsFolder, kwargs):
    historyCounts = [info['historyCount'] for info in simServers_info]

    # step 1: compute the interval sizes (multiples of iRTT)
    minRttAndDuration_methods = []
    for info in simServers_info:
        historyCount, replayPort = info['historyCount'], int(info['replayPort'])

        # if server is local apply local method else send getMeasurement request to remote server
        if socket.gethostbyname(info['server']) == socket.gethostbyname(kwargs['host']):
            pcap_path = get_pcap_filename(userID, info['historyCount'], testID, resultsFolder)
            if pcap_path is None:
                elogger.error('FAILED localization test for {} {}-{}: pcap file missing'.format(userID, *historyCounts))
                return None

            minRttAndDuration_methods.append({'cls': get_minRttAndDuration_from_pcap, 'kwargs': {
                'pcap_file': pcap_path, 'server_port': replayPort}})
        else:
            minRttAndDuration_methods.append({'cls': send_GETMeasurement_request, 'kwargs': {
                'serverIP': info['server'], 'params': {
                    'command': 'getMeasurements', 'measurementType': 'minRttAndDuration', 'userID': userID,
                    'historyCount': historyCount, 'testID': testID, 'kwargs': json.dumps({'serverPort': replayPort})}}})

    minRttsAndDurations = execute_methods_in_parallel(minRttAndDuration_methods)
    if None in minRttsAndDurations:
        elogger.error('FAILED localization test for {} {}: collecting measurements'.format(userID, *historyCounts))
        return None

    min_rtt = max([val['minRtt'] for val in minRttsAndDurations])
    duration = min([val['duration'] for val in minRttsAndDurations])
    interval_sizes = get_interval_sizes(min_rtt, duration)
    if len(interval_sizes) == 0:
        elogger.error('FAILED localization test for {} {}: not enough measurements'.format(userID, *historyCounts))
        return None

    # step 2: compute and collect loss ratio measurements
    lossRatios_methods = []
    for info in simServers_info:
        historyCount, replayPort = info['historyCount'], int(info['replayPort'])

        # if server is local apply local method else send getMeasurement request to remote server
        if socket.gethostbyname(info['server']) == socket.gethostbyname(kwargs['host']):
            pcap_path = get_pcap_filename(userID, info['historyCount'], testID, resultsFolder)
            if pcap_path is None:
                elogger.error('FAILED localization test for {} {}-{}: pcap file missing'.format(userID, *historyCounts))
                return None

            lossRatios_methods.append({'cls': get_lossRatios_from_pcap, 'kwargs': {
                'pcap_file': pcap_path, 'server_port': replayPort, 'interval_sizes': [*interval_sizes, duration]}})
        else:
            lossRatios_methods.append({'cls': send_GETMeasurement_request, 'kwargs': {
                'serverIP': info['server'], 'params': {
                    'command': 'getMeasurements', 'measurementType': 'lossRatios', 'userID': userID, 'historyCount': historyCount,
                    'testID': testID, 'kwargs': json.dumps({'serverPort': replayPort, 'intervalSizes': [*interval_sizes, duration]})}}})

    loss_dfs = execute_methods_in_parallel(lossRatios_methods)
    if np.any([loss_df is None for loss_df in loss_dfs]):
        elogger.error('FAILED localization test for {} {}: collecting measurements'.format(userID, *historyCounts))
        return None

    elif np.any([loss_df.empty for loss_df in loss_dfs]):
        # if there are no loss ratios, we return an empty DataFrame
        return {'simReplaysAvgLoss': [0] * len(loss_dfs), 'spearmanCorrStats': []}


    # step 3: for each interval size: apply spearman corr ratio
    corr_funcs = []
    for interval_size in interval_sizes:
        corr_funcs.append({'cls': compute_perf_correlation,
                           'kwargs': {'pair_perf_dfs': loss_dfs, 'interval_size': interval_size}})
    corr_results = [x for x in execute_methods_in_parallel(corr_funcs) if not(x['corrPVal'] is np.nan)]

    results_as_dict = {
        'simReplaysAvgLoss': [df[df['interval_size'] == duration].perf.iloc[0] for df in loss_dfs],
        'spearmanCorrStats': corr_results
    }
    return results_as_dict


def compare_pairsum_vs_single_replay_xput(userID, testID, simServers_info, singleServer_info, resultsFolder, kwargs):
    historyCounts = [info['historyCount'] for info in simServers_info]

    # step 1: measurement collection: client side throughput samples
    xput_methods = []

    # first get single replay throughput samples
    try:
        singleReplay_historyCount = singleServer_info['singleReplay_historyCount']
        singleServer = singleServer_info['singleReplay_server']
    except:
        elogger.error('FAILED localization test for {} {}: parsing single replay info'.format(userID, *historyCounts))
        return None
    # if server is local apply local method else send getMeasurement request to remote server
    if socket.gethostbyname(singleServer) == socket.gethostbyname(kwargs['host']):
        xput_methods.append({'cls': load_client_xputs, 'kwargs': {
            'userID': userID, 'historyCount': singleReplay_historyCount, 'testID': testID, 'resultsFolder': resultsFolder}})
    else:
        xput_methods.append({'cls': send_GETMeasurement_request, 'kwargs': {
            'serverIP': singleServer, 'params': {
                'command': 'getMeasurements', 'measurementType': 'clientXputs', 'userID': userID,
                'historyCount': singleReplay_historyCount, 'testID': testID, 'kwargs': json.dumps({})}}})

    # next the simultaneous replay throughput samples
    for info in simServers_info:
        historyCount, replayPort = info['historyCount'], int(info['replayPort'])

        # if server is local apply local method else send getMeasurement request to remote server
        if socket.gethostbyname(info['server']) == socket.gethostbyname(kwargs['host']):
            xput_methods.append({'cls': load_client_xputs, 'kwargs': {
                'userID': userID, 'historyCount': historyCount, 'testID': testID, 'resultsFolder': resultsFolder}})
        else:
            xput_methods.append({'cls': send_GETMeasurement_request, 'kwargs': {
                'serverIP': info['server'], 'params': {
                    'command': 'getMeasurements', 'measurementType': 'clientXputs', 'userID': userID,
                    'historyCount': historyCount, 'testID': testID, 'kwargs': json.dumps({})}}})

    xputs = execute_methods_in_parallel(xput_methods)
    if None in xputs:
        elogger.error('FAILED localization test for {} {} - {}: collecting measurements'.format(userID, *historyCounts))
        return None

    # step 2: test if the difference between the total throughput achieved in the single and simultaneous replay (O_diff)
    # is less than the threshold distribution that represent throughput variation due to normal network conditions (T_diff)
    # 1- load T_diff (the current version is collected from )
    # 2- apply Monte-Carlo to compute O_diff
    # 3- apply Mann-Whitney U-Test with alternative hypothesis O_diff and T_diff
    with open(Configs().get('xputDiffThresholds'), "rb") as fp:
        T_diff = np.array(pickle.load(fp))


    if len(xputs) < 3:
        elogger.error('FAILED localization test for {} {} - {}: not enough samples collected'.format(userID, *historyCounts))
        return None
    
    xputs = [x[0] for x in xputs]
    s_xputs = xputs[0]
    psum_xputs = [sum(x) for x in zip(xputs[1], xputs[2])]
    R, N, sub = len(T_diff), min(len(s_xputs), len(psum_xputs)), 0.5
    O_diff = []
    for _ in np.arange(R):
        sub_X1 = np.random.choice(s_xputs, size=int(N * sub), replace=False)
        sub_X2 = np.random.choice(psum_xputs, size=int(N * sub), replace=False)
        sub_avg_X1, sub_avg_X2 = sub_X1.mean(), sub_X2.mean()

        O_diff.append(abs(sub_avg_X1 - sub_avg_X2) / max(sub_avg_X1, sub_avg_X2) * 100)

    U_val, p_val = mannwhitneyu(O_diff, T_diff, alternative='less')

    xput_stats_keys = ['max', 'min', 'average', 'median', 'std']
    results_as_dict = {
        'singleReplayHistoryCount': singleReplay_historyCount,
        'mwuVal': U_val, 'mwuPVal': p_val,
        'simReplaysXputStats': [{k: v for k, v in zip(xput_stats_keys, compute_xput_stats(vals))} for vals in xputs[1:]],
        'simReplaySumXputStats': {k: v for k, v in zip(xput_stats_keys, compute_xput_stats(psum_xputs))},
        'singleReplayXputStats': {k: v for k, v in zip(xput_stats_keys, compute_xput_stats(s_xputs))},
    }
    return results_as_dict


def localize(userID, testID, simServers_info, singleServer_info, kwargs, resultsFolder):
    historyCounts = [int(info['historyCount']) for info in simServers_info]

    loc_decisions_dir = os.path.join(resultsFolder, userID, 'localizeDecisions')
    os.makedirs(loc_decisions_dir, exist_ok=True)
    result_file = '{}/localizeResults_{}_{}-{}_{}.json'.format(loc_decisions_dir, userID, *historyCounts, testID)

    localize_results = {'userID': userID, 'simReplayHistoryCounts': historyCounts, 'testID': testID,
                        'localizeTestsList': [], 'localizeTestsResults': {}}

    # localize will try to test for different differentiation method
    # first per service plan throttling (i.e., ISP handle every plan traffic in dedicated queue)
    results1 = compare_pairsum_vs_single_replay_xput(
        userID, testID, simServers_info, singleServer_info, resultsFolder, kwargs)
    if results1 is not None:
        localize_results['localizeTestsList'].append('pairsum_vs_single_xput')
        localize_results['localizeTestsResults']['pairsum_vs_single_xput'] = results1

    # second per service aggregate policing (i.e., ISP handle all traffic of same service in the same shallow queue)
    results2 = detect_correlated_loss(userID, testID, simServers_info, resultsFolder, kwargs)
    if results2 is not None:
        localize_results['localizeTestsList'].append('loss_correlation')
        localize_results['localizeTestsResults']['loss_correlation'] = results2

    with open(result_file, "w") as writeFile:
        json.dump(localize_results, writeFile)
    bqResultWriter.move_localize_result_file(userID, historyCounts, testID)

    return localize_results


LOC_Queue = gevent.queue.Queue()


def _safe_localize(userID, testID, simServers_info, singleServer_info, kwargs, results_folder):
    try:
        localize(userID, testID, simServers_info, singleServer_info, kwargs, results_folder)
    except Exception as e:
        elogger.error("Localization failed for userID {}, testID {}: {}".format(userID, testID, e))

def runLocalizationTestsProcessor():
    LOG_ACTION(logger, 'Ready to processes localization tests request')

    pool = gevent.pool.Pool()
    while True:
        userID, testID, simServers_info, singleServer_info, kwargs = LOC_Queue.get()
        results_folder = getCurrentResultsFolder()
        pool.apply_async(_safe_localize, args=(userID, testID, simServers_info, singleServer_info, kwargs, results_folder))



class PostLocalizeRequestHandler(AnalyzerRequestHandler):

    @staticmethod
    def getCommandStr():
        return "localize"

    @staticmethod
    def handleRequest(args):
        try:
            userID = args['userID'][0].decode('ascii', 'ignore')
            testID = int(args['testID'][0].decode('ascii', 'ignore'))
            s1_info = json.loads(args['server1Info'][0].decode('ascii', 'ignore'))
            s2_info = json.loads(args['server2Info'][0].decode('ascii', 'ignore'))
            singleServer_info = json.loads(args['singleServerInfo'][0].decode('ascii', 'ignore'))

            kwargs = json.loads(args['kwargs'][0].decode('ascii', 'ignore'))
            kwargs['host'] = args['host']
        except KeyError as e:
            return json.dumps({'success': False, 'missing': str(e)})
        except ValueError as e:
            return json.dumps({'success:': False, 'value error:': str(e)})

        LOC_Queue.put((userID, testID, [s1_info, s2_info], singleServer_info, kwargs))
        LOG_ACTION(logger, 'New localize job added to queue: {}, {} - {}, {}'.format(
            userID, s1_info['historyCount'], s2_info['historyCount'], testID))

        return json.dumps({'success': True})


class GETLocalizeResultRequestHandler(AnalyzerRequestHandler):

    @staticmethod
    def getCommandStr():
        return "localizeResult"

    @staticmethod
    def handleRequest(args):
        try:
            userID = args['userID'][0].decode('ascii', 'ignore')
            historyCounts = [int(x) for x in json.loads(args['historyCounts'][0].decode('ascii', 'ignore'))]
            testID = int(args['testID'][0].decode('ascii', 'ignore'))
        except KeyError as e:
            return json.dumps({'success': False, 'missing': str(e)})
        except ValueError as e:
            return json.dumps({'success:': False, 'value error:': str(e)})

        result_folder = getCurrentResultsFolder()
        result_file = '{}/{}/localizeDecisions/localizeResults_{}_{}-{}_{}.json'.format(
            result_folder, userID, userID, *historyCounts, testID)

        # check if results are ready
        if not os.path.isfile(result_file):
            LOG_ACTION(logger, 'result not ready yet :{}, {}-{}, {}'.format(userID, *historyCounts, testID))
            return json.dumps({'success': False, 'error': 'No result found'})

        with open(result_file, "r") as json_file:
            results = json.load(json_file)

        response = {'userID': userID, 'historyCounts': historyCounts, 'testID': str(testID),
                    'localization_tests': results['localizeTestsList']}
        test_results = results['localizeTestsResults']

        if 'pairsum_vs_single_xput' in results['localizeTestsList']:
            stats = test_results['pairsum_vs_single_xput']
            response['pairsum_vs_single_xput'] = {
                'mwuVal': stats['mwuVal'], 'mwuPVal': stats['mwuPVal'],
                'simReplaysAvgXput': [s['average'] for s in stats['simReplaysXputStats']],
                'simReplaySumAvgXput': stats['simReplaySumXputStats']['average'],
                'singleReplayAvgXput': stats['singleReplayXputStats']['average'],
            }

        if 'loss_correlation' in results['localizeTestsList']:
            stats = test_results['loss_correlation']
            response['loss_correlation'] = {
                'intervalSizes': [s['intervalSize'] for s in stats['spearmanCorrStats']],
                'corrPValues': [s['corrPVal'] for s in stats['spearmanCorrStats']],
                'simReplaysAvgLoss': stats['simReplaysAvgLoss']
            }
        return json.dumps({'success': True, 'response': response}, cls=myJsonEncoder)