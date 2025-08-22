FROM ubuntu:20.04

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install --yes \
   apt-utils gcc libc-dev libcap2-bin libmysqlclient-dev python3 python3-pip \
   tcpdump tcpreplay tshark wireshark scapy netcat apt-transport-https ca-certificates gnupg curl


RUN curl -s https://packagecloud.io/install/repositories/github/git-lfs/script.deb.sh | bash \
    && DEBIAN_FRONTEND=noninteractive apt-get install --yes git-lfs
  
RUN pip3 install timezonefinder future gevent matplotlib multiprocessing_logging "mysqlclient<2.1.1" \
  netaddr prometheus_client psutil reverse-geocode reverse-geocoder \
  "tornado<6.0.0" "urllib3<2.0" google-cloud-bigquery requests pandas bs4 lxml pytest

# Allow user nobody to execute tcpdump, and add CAP_NET_RAW capability to the
# tcpdump binary.
RUN chgrp tcpdump /usr/sbin/tcpdump && adduser nobody tcpdump
RUN setcap cap_net_raw=ep /usr/sbin/tcpdump

ARG REPO_URL=https://github.com/NEU-SNS/wehe-py3.git

RUN git clone $REPO_URL \
    && mv wehe-py3/replayTraces /replayTraces \
    && mv wehe-py3/src /wehe \
    && mv wehe-py3/uuid_prefix_tag.txt /uuid_prefix_tag.txt \
    && rm -rf wehe-py3

# ADD src /wehe
# ADD replayTraces /replayTraces
# ADD uuid_prefix_tag.txt /uuid_prefix_tag.txt
WORKDIR /wehe
# You must provide a local hostname argument when you start this image, as well
# as the net interface to listen on.
ENTRYPOINT ["/bin/bash", "./startserver.sh"]