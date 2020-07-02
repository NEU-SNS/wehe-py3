#!/bin/bash

screen -X -S analyzer quit
screen -X -S replay quit

sleep 5

cd /home/ubuntu/wehe-py3/src/

screen -S analyzer -d -m sudo python3 replay_analyzerServer.py --ConfigFile=configs.cfg --original_ports=True

echo Started replay analyzer

sleep 5

screen -S replay -d -m sudo python3 replay_server.py --ConfigFile=configs.cfg --original_ports=True

echo Started replay server
