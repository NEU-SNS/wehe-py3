FROM ubuntu:20.04

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install --yes \
   apt-utils gcc libc-dev libcap2-bin libmysqlclient-dev python3 python3-pip \
   tcpdump tcpreplay tshark wireshark scapy netcat

RUN pip3 install timezonefinder future gevent matplotlib multiprocessing_logging mysqlclient \
  netaddr prometheus_client psutil reverse-geocode reverse-geocoder \
  "tornado<6.0.0" "urllib3<2.0" google-cloud-bigquery

# Allow user nobody to execute tcpdump, and add CAP_NET_RAW capability to the
# tcpdump binary.
RUN chgrp tcpdump /usr/sbin/tcpdump && adduser nobody tcpdump
RUN setcap cap_net_raw=ep /usr/sbin/tcpdump

ADD src /wehe
ADD replayTraces /replayTraces
ADD res /res
WORKDIR /wehe
# You must provide a local hostname argument when you start this image, as well
# as the net interface to listen on.
ENTRYPOINT ["/bin/bash", "./startserver.sh"]
