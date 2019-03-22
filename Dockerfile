#FROM ubuntu:16.04
FROM golang:1.12.1-stretch

RUN apt-get update && \
    apt-get -y -q install wget lsb-release gnupg && \
    wget -q http://apt-stable.ntop.org/16.04/all/apt-ntop-stable.deb && \
    dpkg -i apt-ntop-stable.deb && \
    apt-get clean all

RUN apt-get update && \
    apt-get -y install pfring libpcap-dev

COPY src/packetcapture src/packetcapture

RUN go get -u github.com/google/gopacket && go build packetcapture

#COPY packetcapture /packetcapture

#CMD /packetcapture
