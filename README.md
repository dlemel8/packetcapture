[![Build Status](https://travis-ci.org/dlemel8/packetcapture.svg?branch=master)](https://travis-ci.org/dlemel8/packetcapture)

# packetcapture
A simple program to compare traffic capture technologies: 
* libpcap
* pfring
* afpacket

## Overview
All those technologies work in a similar method:
* This tool initializes one or more (if the method supports fanout) sockets. Each socket is assigned one buffer in the kernel. If BPF is set, it is compiled and attached to the socket.
* A packet comes from the NIC to the relevant driver, which wraps the information in a generic Linux structure (sk_buff) and puts it in a queue for CPU processing.
* The CPU looks at the first packet in the queue. Instead of calling all the processes of the IP Stack (spreading and removing each header, calling netfilter hooks, etc.), it looks for the relevant socket object.
* If BPF is attached to the socket, CPU checks if the packet passes it. If not, packet is thrown away.
* The packet is copied to our kernel buffer and then removed from the queue.
* From here this tool can copy the information to the user space or work on it while it is still in the buffer (called "zero copy" in gopacket).

## Usage
You can use this tool to sniff a network device in one of the methods. 
You can set the kernel buffers number, whether to use zero copy, and BPF.
The tool will print pps and packet loss every second.
Keep in mind that the tool does nothing with the packets it receives, so the numbers you see represent the maximum traffic that can be handled according to the settings.
