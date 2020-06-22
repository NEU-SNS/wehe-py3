FROM python:3
MAINTAINER Fangfan Li <li.fa@husky.neu.edu>
RUN pip install --upgrade pip
RUN apt-get update
RUN apt-get install gcc
RUN apt-get install libc-dev
RUN apt-get install -y tcpdump
RUN apt-get install -y tcpreplay
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y wireshark
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y tshark
RUN pip3 install --no-cache matplotlib
RUN pip3 install --no-cache psutil
RUN pip3 install --no-cache mysqlclient
RUN pip3 install --no-cache "tornado<6.0.0"
RUN pip3 install --no-cache multiprocessing_logging
RUN pip3 install --no-cache netaddr
RUN pip3 install --no-cache future
RUN pip3 install --no-cache timezonefinder
RUN pip3 install --no-cache gevent
RUN pip3 install --no-cache reverse-geocoder
RUN pip3 install --no-cache reverse-geocode
RUN pip3 install --no-cache prometheus_client
ADD src /wehe
ADD replayTraces /replayTraces
WORKDIR /wehe
# You must provide a local hostname argument when you start this image.
ENTRYPOINT ["/bin/sh", "./startserver.sh"]