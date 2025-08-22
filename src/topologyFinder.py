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
import os, gevent, datetime, shutil, requests, bs4, urllib, re, hashlib

import numpy as np
import pandas as pd

import gevent.monkey
gevent.monkey.patch_all(ssl=False)

from python_lib import *


def is_valid_ip(ip):
    try:
        ipaddress.ip_network(ip)
        return True
    except:
        return False


def belongs_to_network(ip_addr, network_addr):
    try:
        return ipaddress.ip_address(ip_addr) in ipaddress.ip_network(network_addr)
    except:
        return False


def get_smallest_network(network_addrs):
    networks_dict = {addr.split('/')[1]: addr for addr in network_addrs}
    return networks_dict[max(networks_dict.keys())] if (len(networks_dict.keys()) != 0) else None


######################### Methods for handling hops with missing network info #########################
def get_PCH_ixp_prefixes(ixp_id):
    try:
        return [record['subnet'] for record in requests.get(f'https://www.pch.net/api/ixp/subnets/{ixp_id}').json()]
    except:
        return None


def download_PCH_ixps():
    try:
        ixps_df = pd.DataFrame(requests.get('https://www.pch.net/api/ixp/directory/Any').json())
        ixps_df['prefix'] = ixps_df['id'].apply(get_PCH_ixp_prefixes)
        ixps_df = ixps_df.explode('prefix').reset_index(drop=True)
        return ixps_df[['prefix', 'name', 'url']]
    except:
        return None


def get_HE_ixp_prefixes(ixp_href, http_session):
    try:
        tab_data = bs4.BeautifulSoup(
            http_session.get(ixp_href).text, "html.parser").body.find_all('div', attrs={'id': 'exchange'})[0]
        prefixes = []
        for ele in tab_data.find_all('div', attrs={'class': 'asright'}):
            prefixes += [str(ipaddress.ip_network(addr)) for addr in ele.text.strip().split(',') if is_valid_ip(addr)]
        return prefixes
    except:
        return None


def download_HE_ixps():
    try:
        data = bs4.BeautifulSoup(requests.get('https://bgp.he.net/report/exchanges').text, "html.parser")
        table = data.body.find_all('table', attrs={'id': 'exchangestable'})[0]

        ixps_df = html_table_to_df(table)

        session = requests.Session()
        ixps_prefixes = []
        for row in table.find_all('tr'):
            cols = row.find_all('td')
            if cols:
                ixps_prefixes.append({
                    'Internet Exchange': cols[0].text.strip(),
                    'prefix': get_HE_ixp_prefixes('https://bgp.he.net/{}'.format(cols[0].find('a')['href']), session)})
        session.close()

        ixps_df = pd.merge(ixps_df, pd.DataFrame(ixps_prefixes), on='Internet Exchange')
        ixps_df = ixps_df.explode('prefix').reset_index(drop=True).rename(
            columns={"Internet Exchange": "name", "Website": "url"})
        return ixps_df[['prefix', 'name', 'url']]
    except:
        return None


def download_ixps_dataset(dir):
    ixps_file = os.path.join(dir, 'ixps.csv')
    if not os.path.exists(ixps_file):
        he_ixps_df = download_HE_ixps().dropna(subset=['prefix'])
        he_ixps_df['source'] = 'Hurricane Electric'

        pch_ixps_df = download_PCH_ixps().dropna(subset=['prefix'])
        pch_ixps_df['source'] = 'PCH: Packet Clearing House'
        pch_ixps_df['url'] = pch_ixps_df['url'].apply(get_domain_from_url)

        ixps_df = pd.concat([
            he_ixps_df,
            pch_ixps_df[~pch_ixps_df['prefix'].isin(he_ixps_df['prefix'].values)]
        ]).dropna(subset=['prefix']).reset_index(drop=True)
        ixps_df['id'] = ixps_df['name'].apply(
            lambda name: int(hashlib.shake_128(str(name).encode('utf-8')).hexdigest(4), 16))

        ixps_df.to_csv(ixps_file, index=None)
    return pd.read_csv(ixps_file)


def check_if_ixp(ip_addr, ixps_df):
    record = ixps_df[ixps_df['prefix'].apply(lambda network: belongs_to_network(ip_addr, network))]
    if record.shape[0] == 1:
        info = record.iloc[0].to_dict()
        return True, 'IXP:{}'.format(info['prefix']), (int(info['id']) * -1) if info['id'] else None, info['name']
    return False, None, None, None


def find_whois_annotations(ip_addr):
    cidr, as_number, as_name = None, None, None
    for i in np.arange(3):
        try:
            outs, _ = subprocess.Popen(
                ['whois', ip_addr], stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
            outs = outs.decode('ISO-8859-1')

            cidrs = re.findall(r"[\d.:a-zA-Z]*/\d+", outs)
            valid_cidrs = [cidr for cidr in cidrs if is_valid_ip(cidr) & belongs_to_network(ip_addr, cidr)]
            cidr = get_smallest_network(valid_cidrs)

            outs, _ = subprocess.Popen(
                ['whois', cidr.split('/')[0]], stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
            outs = outs.decode('ISO-8859-1')

            as_number = [asn.replace('AS', '') for asn in list(set(re.findall(r"AS\d+", outs)))][-1]
            as_name = requests.get(f'https://api.bgpview.io/asn/{as_number}').json()['data']['description_short']
            break
        except:
            pass
    return (as_number is not None),cidr, as_number, as_name


def annotate_traceroute(traceroute, ixps_dataset):
    is_valid, has_changed = True, False
    for hop in traceroute:
        if hop['missing_network'] in ('true', 'false'):
            hop['missing_network'] = hop['missing_network'] == 'true'
        if hop['missing_network']:
            is_annotated, cidr, asn, asname = check_if_ixp(hop['hop_addr'], ixps_dataset)
            if not is_annotated:
                is_annotated, cidr, asn, asname = find_whois_annotations(hop['hop_addr'])
            if is_annotated:
                hop['missing_network'] = not is_annotated
                hop['hop_CIDR'], hop['hop_ASN'], hop['hop_ASName'] = cidr, asn, asname
            has_changed = True
        is_valid = is_valid and (not hop['missing_network'])
    return is_valid, has_changed
#######################################################################################################


##################### Methods for downloading and checking network's upstream info ####################
def get_HE_as_upstreams(asn):
    try:
        data = bs4.BeautifulSoup(requests.get(f'https://bgp.he.net/AS{asn}').text, "html.parser").body.find_all(
            'div', attrs={'id': 'historical-charts'})[0]

        table4 = data.find_all('div', attrs={'class': 'floatright'})[0].find_all('table')[0]
        upstreams4 = html_table_to_df(table4).rename(columns={'ASN': 'asn', 'Name': 'name'})
        upstreams4['asn'] = upstreams4['asn'].apply(lambda s: s.replace('AS', ''))
        upstreams4 = upstreams4.to_dict('records')

        table6 = data.find_all('div', attrs={'class': 'floatright'})[1].find_all('table')[0]
        upstreams6 = html_table_to_df(table6).rename(columns={'ASN': 'asn', 'Name': 'name'})
        upstreams6['asn'] = upstreams6['asn'].apply(lambda s: s.replace('AS', ''))
        upstreams6 = upstreams6.to_dict('records')

        upstreams = {
            'upstreams4': {int(r['asn']): r for r in upstreams4},
            'upstreams6': {int(r['asn']): r for r in upstreams6}}
        return upstreams
    except:
        return {'upstreams4': {}, 'upstreams6': {}}


def download_CAIDA_as_relationships(dir):
    as_upstreams_file = os.path.join(dir, 'CAIDA_as_upstreams.csv')
    if not os.path.exists(as_upstreams_file):
        try:
            temp_file = os.path.join(dir, 'temp.txt')

            subprocess.run(
                ['curl', '-o', f'{temp_file}.bz',
                 'https://publicdata.caida.org/datasets/as-relationships/serial-2/20240201.as-rel2.txt.bz2'],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            subprocess.run(['bzip2', '-d', f'{temp_file}.bz'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            with open(temp_file, 'r') as f:
                p2c_rels_lines = [l.strip().split('|') for l in f.readlines() if
                                  re.fullmatch('[0-9]+\|[0-9]+\|-1\|.*\n', l)]
            upstreams_df = pd.DataFrame([{'asn': rel[1], 'upstream': rel[0]} for rel in p2c_rels_lines])

            upstreams_df.to_csv(as_upstreams_file, index=None)
            os.remove(temp_file)
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            return None
    return pd.read_csv(as_upstreams_file)


def get_CAIDA_as_upstreams(asn, upstreams_df):
    upstreams = {}
    upstreams_asns = upstreams_df[(upstreams_df['asn'] == int(asn)) | (upstreams_df['asn'] == str(asn))]['upstream'].values
    for upstream_asn in upstreams_asns:
        try:
            data = requests.get(f'https://api.bgpview.io/asn/{upstream_asn}').json()['data']
            upstreams[str(upstream_asn)] = {"asn": data['asn'], "name": data['description_short']}
        except:
            continue
    return {'upstreams4': upstreams, 'upstreams6': upstreams}


def get_as_upstreams(asn, dir, caida_upstreams_df):
    bgp_file = os.path.join(dir, f'upstreams_{asn}.json')

    # if it is cached, just return
    if os.path.exists(bgp_file):
        with open(bgp_file, 'r') as json_file:
            return json.load(json_file)

    # find and process bgp informartion from all sources
    bgp_info = {'HE': get_HE_as_upstreams(asn),
                'CAIDA': get_CAIDA_as_upstreams(asn, caida_upstreams_df)}

    upstreams4, upstreams6 = [], []
    for data_src in bgp_info.keys():
        upstreams4 = upstreams4 + list(bgp_info[data_src]['upstreams4'].keys())
        upstreams6 = upstreams6 + list(bgp_info[data_src]['upstreams6'].keys())

    upstreams = {'upstreams4': [int(k) for k in list(set(upstreams4))],
                 'upstreams6': [int(k) for k in list(set(upstreams6))]}
    with open(bgp_file, 'w') as json_file:
        json.dump(upstreams, json_file)

    return upstreams


def check_upstream_info(client_info, traceroute, as_upstreams):
    client_asn = client_info['ASN']
    client_upstream = int([hop for hop in traceroute if hop['hop_ASN'] != client_asn][-1]['hop_ASN'])
    return (client_upstream < 0) or (client_upstream in as_upstreams)
#######################################################################################################


######################### Methods for downloading and processing the topologies #######################
def getYTopologiesGCSUrls(date):
    ytopos_urls = {}   
    bucket_root = Configs().get('toposDb')
    bucket_prefix = f"{Configs().get('topologiesPrefix')}{date}/"
    r = requests.get(bucket_root, params={"prefix": bucket_prefix, "delimiter": "/"})
    
    LOG_ACTION(logger, f'topologies: {r.text}')
    if r.status_code == 200:
        content = bs4.BeautifulSoup(r.text, "xml")
        for key in content.find_all("Key"):
            subnet = re.search(rf"{re.escape(bucket_prefix)}ytopologies-(.*?)-(.*?)-.*\.json$", key.getText())
            if subnet:
                ytopos_urls['/'.join(subnet.groups())] = urllib.parse.urljoin(bucket_root, key.getText())
    return ytopos_urls


def recheck_topology(topo, client_as_upstreams, ixps_dataset, client_info):
    # first check if the traceroutes are valid and if they have changed
    trs_valid, trs_changed = True, False
    for traceroute in topo['traceroutes'].values():
        all_hops_annotated, tr_changed = annotate_traceroute(traceroute, ixps_dataset)
        correct_upstream = check_upstream_info(client_info, traceroute, client_as_upstreams)
        trs_valid = trs_valid and (all_hops_annotated and correct_upstream)
        trs_changed = trs_changed or tr_changed

    # second check if the path-pair topology after the change is still Y-shaped
    if trs_changed and trs_valid:
        asns_dfs = []
        for traceroute in topo['traceroutes'].values():
            tr_df = pd.DataFrame(traceroute)
            tr_df = tr_df[tr_df['hop_ASN'] != client_info['ASN']]
            asns_df = tr_df.groupby(['hop_ASN', 'hop_ASName'])['offset'].agg(min).reset_index()
            asns_df['offset'] = asns_df.apply(lambda row: asns_df.shape[0] - row.name, axis=1)
            asns_dfs.append(asns_df)

        common_asns = pd.merge(asns_dfs[0], asns_dfs[1], on=['hop_ASN', 'hop_ASName'], suffixes=['1', '2'])
        are_offsets_equal = np.all(common_asns['offset1'] == common_asns['offset2'])
        are_offset_consec = np.all(common_asns['offset1'] == common_asns['offset1'].shift(1, fill_value=0) + 1)
        is_yshaped = are_offsets_equal and are_offset_consec
        if is_yshaped:
            topo['common_outside_ases'] = common_asns.to_dict('records')
        return is_yshaped

    return trs_valid


def downloadYTopologiesPerSubnet(gcs_url, local_file, kwargs):
    try:
        data = requests.get(gcs_url).json()

        ip_version = ipaddress.ip_network(data['subnet']).version
        as_upstreams = get_as_upstreams(
            data['ASN'], kwargs['upstreams-dir'], kwargs['caida-upstreams-df'])[f'upstreams{ip_version}']
        
        client_info = {'ASN': data['ASN'], 'subnet': data['subnet']}
        data['topos'] = [topo for topo in data['topos'] if recheck_topology(topo, as_upstreams, kwargs['ixps_dataset'], client_info)]
        if len(data['topos']) > 0:
            with open(local_file, 'w') as jsonfile:
                json.dump(data, jsonfile)
    except Exception as e:
        print("Error downloading Y-topologies for url: ", gcs_url, ": ", e)
        pass


def downloadYTopologies(date):
    # check if the json files are available in GCS and wait until they are available
    ytopos_urls = getYTopologiesGCSUrls(date)
    while len(ytopos_urls) == 0:
        LOG_ACTION(logger, 'topologies are still not available.')
        gevent.sleep(60)
        ytopos_urls = getYTopologiesGCSUrls(date)

    # prepare the cache directory (make sure to remove the old versions)
    topo_cache = os.path.join(Configs().get('tmpCacheFolder'), 'ytopologies')
    if os.path.exists(topo_cache) and os.path.isdir(topo_cache):
        shutil.rmtree(topo_cache)
    os.makedirs(topo_cache, exist_ok=True)

    # prepare datasets used for validating traceroute in the topologies
    datasets_cache = os.path.join(Configs().get('tmpCacheFolder'), 'res')
    if os.path.exists(datasets_cache) and os.path.isdir(datasets_cache):
        shutil.rmtree(datasets_cache)

    # IXPs dataset
    ixps_cache = os.path.join(datasets_cache, 'ixps')
    os.makedirs(ixps_cache, exist_ok=True)
    ixps_dataset = download_ixps_dataset(ixps_cache)

    # upstreams info
    upstreams_cache = os.path.join(datasets_cache, 'as-upstreams-info')
    os.makedirs(upstreams_cache, exist_ok=True)
    upstreams_df = download_CAIDA_as_relationships(upstreams_cache)

    kwargs = {'upstreams-dir': upstreams_cache, 'caida-upstreams-df': upstreams_df, 'ixps_dataset': ixps_dataset}

    # download the json files for GCS
    for subnet in ytopos_urls.keys():
        local_file = os.path.join(topo_cache, 'ytopologies-{}-{}.json'.format(*subnet.split('/')))
        downloadYTopologiesPerSubnet(ytopos_urls[subnet], local_file, kwargs)
    LOG_ACTION(logger, 'Topologies are downloaded.')


def runScheduledYTopologiesDownload():
    LOG_ACTION(logger, "scheduling download")
    download_time = datetime.time(hour=0, minute=30, second=0)
    while True:
        date = time.strftime("%Y-%m-%d", time.gmtime())
        downloadYTopologies(date)
        
        curr_time = datetime.datetime.now()
        next_time = datetime.datetime.combine(datetime.datetime.today() + datetime.timedelta(days=1), download_time)
        time_interval = (next_time-curr_time).total_seconds()
        LOG_ACTION(logger, 'Next download scheduled on {}, which is in {}sec.'.format(next_time, time_interval))

        gevent.sleep(time_interval)

        
def computeServerPairs(ytopologies):
    server_site_pairs, server_ip_pairs = set(), set()
    
    for topo in ytopologies['topos']:
        networks = ' or '.join(set(
            [common_as['hop_ASName'] for common_as in topo['common_outside_ases']] + [ytopologies['ASName']]))

        if topo['servers']['s1']['mlab_site'] and topo['servers']['s2']['mlab_site']:
            server_site_pairs.add((
                topo['servers']['s1']['mlab_site'], topo['servers']['s2']['mlab_site'], networks))

        if topo['servers']['s1']['IP'] and topo['servers']['s2']['IP']:
            server_ip_pairs.add((
                topo['servers']['s1']['IP'], topo['servers']['s2']['IP'], networks))
    return list(server_site_pairs), list(server_ip_pairs)
    
#######################################################################################################


def getTopologyFilepath(ip_addr, dir):
    for filename in os.listdir(dir):
        subnet = '{}/{}'.format(*filename.replace('.json', '').split('-')[1:3])
        if belongs_to_network(ip_addr, subnet):
            return os.path.join(dir, filename)
    return None


class GetServersAnalyzerRequestHandler(AnalyzerRequestHandler):
    @staticmethod
    def getCommandStr(): return "getServers"

    @staticmethod
    def handleRequest(args):
        try:
            clientIP = args['clientIP'][0].decode('ascii', 'ignore')
        except KeyError as e:
            return json.dumps({'success': False, 'missing': str(e)})

        filepath = getTopologyFilepath(clientIP, os.path.join(Configs().get('tmpCacheFolder'), 'ytopologies'))


        # handle case client have no y-shaped topology
        if filepath is None:
            return json.dumps({'success': False, 'error': 'No Y-topology found.'})

        with open(filepath) as json_file:
            ytopologies = json.load(json_file)

        server_site_pairs, server_ip_pairs = computeServerPairs(ytopologies)

        if (len(server_site_pairs) == 0) and (len(server_ip_pairs) == 0):
            return json.dumps({'success': False, 'error': 'No Y-topology found.'})
        return json.dumps({'success': True, 'response': {
            'server-site-pairs': list(server_site_pairs),
            'server-ip-pairs': list(server_ip_pairs)}}, cls=myJsonEncoder)



