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
import os, gevent, datetime, shutil

import gevent.monkey
gevent.monkey.patch_all(ssl=False)

from python_lib import *


def downloadYTopologies():
    date = time.strftime("%Y-%m-%d", time.gmtime())
    url = '{}/{}'.format(Configs().get('toposDb'), date)
    topo_db = os.path.join(Configs().get('tmpCacheFolder'), 'ytopologies')

    # first make sure to remove the old versions
    if os.path.exists(topo_db) and os.path.isdir(topo_db):
        shutil.rmtree(topo_db)

    # download new data
    os.makedirs(topo_db, exist_ok=True)
    while not downloadWebpageContent(url, topo_db):
        LOG_ACTION(logger, 'topologies at {} are still not available.'.format(url))
        gevent.sleep(60)
    LOG_ACTION(logger, 'Topologies are downloaded from {}.'.format(url))


def runScheduledYTopologiesDownload():
    print('method called')
    download_time = datetime.time(hour=12, minute=0, second=0)
    while True:
        downloadYTopologies()

        curr_time = datetime.datetime.now()
        next_time = datetime.datetime.combine(datetime.datetime.today() + datetime.timedelta(days=1), download_time)
        time_interval = (next_time-curr_time).total_seconds()
        LOG_ACTION(logger, 'Next download scheduled on {}, which is in {}sec.'.format(next_time, time_interval))

        gevent.sleep(time_interval)


class GetServersAnalyzerRequestHandler(AnalyzerRequestHandler):
    @staticmethod
    def getCommandStr(): return "getServers"

    @staticmethod
    def handleRequest(args):
        try:
            userIP = args['userIP'][0].decode('ascii', 'ignore')
        except KeyError as e:
            return json.dumps({'success': False, 'missing': str(e)})

        filepath = os.path.join(
            Configs().get('tmpCacheFolder'), 'ytopologies',
            'ytopologies-{}-000000000000.json'.format(get_anonymizedIP(userIP)))

        # handle case client have no y-shaped topology
        if not os.path.exists(filepath):
            return json.dumps({'success': False, 'error': 'No Y-topology found.'})

        with open(filepath) as json_file:
            ytopologies = json.load(json_file)

        servers_list = set()
        for topo in ytopologies:
            site_info_s1 = topo['servers']['s1']['server_site']
            site_info_s2 = topo['servers']['s2']['server_site']
            servers_list.add((site_info_s1, site_info_s2))

        if len(servers_list) == 0:
            return json.dumps({'success': False, 'error': 'No Y-topology found.'})
        return json.dumps({'success': True, 'response': {'server-pairs': list(servers_list)}}, cls=myJsonEncoder)
