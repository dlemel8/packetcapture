FROM golang:1.12.1-stretch AS builder

RUN apt-get update && \
    apt-get -y -q install wget lsb-release gnupg && \
    wget -q http://apt-stable.ntop.org/16.04/all/apt-ntop-stable.deb && \
    dpkg -i apt-ntop-stable.deb && \
    apt-get clean all

RUN apt-get update && \
    apt-get -y install pfring libpcap-dev && \
    go get -u golang.org/x/net/bpf && \
    go get -u golang.org/x/sys/unix && \
    go get -u github.com/google/gopacket

COPY src/packetcapture src/packetcapture
RUN go build packetcapture



FROM ubuntu:16.04

COPY --from=builder /go/apt-ntop-stable.deb /apt-ntop-stable.deb
RUN apt-get update && \
    apt-get -y -q install lsb-release gnupg && \
    dpkg -i /apt-ntop-stable.deb && \
    apt-get clean all

RUN apt-get update && \
    apt-get -y install pfring libpcap-dev && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /go/packetcapture /packetcapture

#CMD /packetcapture

