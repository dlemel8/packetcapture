FROM ubuntu:16.04

RUN apt-get update && \
    apt-get -y -q install wget lsb-release gnupg && \
    wget -q http://apt-stable.ntop.org/16.04/all/apt-ntop-stable.deb && \
    dpkg -i apt-ntop-stable.deb && \
    apt-get clean all

RUN apt-get update && \
    apt-get -y install pfring libpcap-dev

COPY packetcapture /packetcapture

# run with --net=host
CMD /packetcapture
