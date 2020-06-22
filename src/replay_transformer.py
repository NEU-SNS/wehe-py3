import argparse
from os import path
import os
import pickle
import json

parser = argparse.ArgumentParser(
    description='Perform transformations to a given replay')
parser.add_argument('--output', metavar='<path>', type=str,
                    help='path where to put the new replay', default='')
parser.add_argument('--source', metavar='', type=str,
                    help='path to replay folder', default='./')
parser.add_argument('--new_port', metavar='<port>', type=str,
                    help='new port for the replay', default='')
parser.add_argument('--new_name', metavar='<name>', type=str,
                    help='new name for the replay', default='')

args = parser.parse_args()
print(args)

if args.output == '' or args.source == '':
    print("please provide the source folder and the destination folder")
    exit()

# temp_path = '/home/ubuntu/Pickles_Server/CloudFlare_03232020'
temp_path = args.source

replay_name = temp_path.split('/')[-1]

server_pickle = path.join(temp_path, replay_name + '.pcap_server_all.pickle')
client_json = path.join(temp_path, replay_name + '.pcap_client_all.json')
Q, tmpLUT, tmpgetLUT, udpServers, tcpServerPorts, replayName = pickle.load(
    open(server_pickle, 'br'))


def replace_connection_port(old, port):
    addresses = old.split('-')
    client = addresses[0]
    server = addresses[1]
    new_port = port
    while len(new_port) < 5:
        new_port = '0' + new_port

    type_test = server.split('.')
    if len(type_test) == 2:
        server_ip = type_test[0]
        server_port = type_test[1]
    else:
        server_ip = type_test[0:len(type_test) - 1]
        server_port = type_test[-1]

    new_server = '.'.join([server_ip, new_port])
    new_connection = '-'.join([client, new_server])
    return new_connection


for protocol in Q:
    for connection in Q[protocol]:
        if args.new_port != '':
            Q[protocol][replace_connection_port(
                connection, args.new_port)] = Q[protocol].pop(connection)

for procol in tmpLUT:
    for connection in tmpLUT[protocol]:
        replay, connection_info = tmpLUT[protocol][connection]

        if args.new_name != '':
            replay = args.new_name
        if args.new_port != '':
            tmpLUT[protocol][connection] = (
                replay, replace_connection_port(connection_info, args.new_port))

for connection in tmpgetLUT:
    replay, info = connection
    if args.new_name != '':
        replay = args.new_name
    if args.new_port != '':
        new_connection = (replay, replace_connection_port(info, args.new_port))
        tmpgetLUT[new_connection] = tmpgetLUT.pop(connection)

if args.new_port != '':
    new_port = args.new_port
    while len(new_port) < 5:
        new_port = '0' + new_port
    tcpServerPorts = [new_port]

if args.new_name != '':
    replayName = args.new_name

with open(client_json) as json_file:
    loaded_json = json.load(json_file)
    replay = loaded_json[0]
    unknown = loaded_json[1]
    connection = loaded_json[2]
    replay_name = loaded_json[3]

    if args.new_name != '':
        replay_name = args.new_name

    for pair in replay:
        if args.new_port != '':
            pair['c_s_pair'] = replace_connection_port(
                pair['c_s_pair'], args.new_port)

    if args.new_port != '':
        new_connections = []
        for con in connection:
            new_connections.append(
                replace_connection_port(con, args.new_port))

    new_json = [replay, unknown, new_connections, replay_name]

os.makedirs(args.output, exist_ok=True)

if args.new_name != '':
    replay_name = args.new_name

new_server_pickle = path.join(
    args.output, replay_name + '.pcap_server_all.pickle')
new_client_json = path.join(
    args.output, replay_name + '.pcap_client_all.json')

with open(new_client_json, 'w') as outfile:
    json.dump(new_json, outfile)

pickle.dump((Q, tmpLUT, tmpgetLUT, udpServers, tcpServerPorts, replayName),
            open((new_server_pickle), "wb"), 2)
