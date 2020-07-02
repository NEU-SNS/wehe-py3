#!/bin/bash

set -euxo pipefail

HOSTNAME=${1:?The first argument to this script should be the local hostname.}
INTERFACE=${2:-default ?The second argument to this script should be the network interface to listen to.}
# First, generate the certificates from certificate authority.
python3 certGenerator.py \
   --destination=/wehe/ssl/ \
   --domain_name=${HOSTNAME} \
   --root_key=/wehe/ssl/ca.key \
   --root_cert=/wehe/ssl/ca.crt \
   --root_pass=wehepower2HjBqmhqF4

# Now start two servers.
# The replay analyzer
python3 replay_analyzerServer.py \
  --ConfigFile=configs.cfg \
  --original_ports=True \
  --certs-folders=/wehe/ssl/ \
  &

# The replay server
python3 replay_server.py \
  --ConfigFile=configs.cfg \
  --original_ports=True \
  --certs-folders=/wehe/ssl/ \
  --tcpdumpInt=${INTERFACE} \
  &

# Wait for both servers to terminate.
wait
