package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pfring"
	"time"
)

type packetsCaptureStrategy interface {
	create(device string) (*gopacket.PacketSource, error)
}


type native struct {

}

func (native) create(device string) (*gopacket.PacketSource, error) {
	handle, err := pcap.OpenLive(device, 1024, true, 30*time.Second)
	if err != nil {
		return nil, err
	}
	//defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	return packetSource, nil
}

type pfRing struct {

}

func (pfRing) create(device string) (*gopacket.PacketSource, error) {
	ring, err := pfring.NewRing(device, 65536, pfring.FlagPromisc)
	if err != nil {
		return nil, err
	}
	if err = ring.SetSocketMode(pfring.ReadOnly); err != nil {
		return nil, err
	}
	if err = ring.SetDirection(pfring.ReceiveOnly); err != nil {
		return nil, err
	}
	if err = ring.Enable(); err != nil {
		return nil, err
	}
	packetSource := gopacket.NewPacketSource(ring, layers.LinkTypeEthernet)
	return packetSource, nil
}

var strategies = map[string]packetsCaptureStrategy {
	"pcap": &native{},
	"pfring": &pfRing{},
}

func getStrategyNames() []string {
	var keys []string
	for k := range strategies {
		keys = append(keys, k)
	}
	return keys
}
