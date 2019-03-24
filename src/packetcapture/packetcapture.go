package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pfring"
	"time"
)

const maxPacketSize = 65536

type packetsCaptureStrategy interface {
	create(device string) ([]*gopacket.PacketSource, error)
	destroy()
}

type native struct {
	handle *pcap.Handle
}

func (n *native) create(device string) ([]*gopacket.PacketSource, error) {
	var err error

	n.handle, err = pcap.OpenLive(device, maxPacketSize, true, 30*time.Second)
	if err != nil {
		return nil, err
	}

	packetSource := gopacket.NewPacketSource(n.handle, n.handle.LinkType())
	return []*gopacket.PacketSource{packetSource}, nil
}

func (n *native) destroy() {
	n.handle.Close()
}

type pfRing struct {
	cluster int
	rings   []*pfring.Ring
}

func (p *pfRing) create(device string) ([]*gopacket.PacketSource, error) {
	var res []*gopacket.PacketSource

	for i := 0; i < 4; i++ {
		ring, err := pfring.NewRing(device, maxPacketSize, pfring.FlagPromisc)
		if err != nil {
			return nil, err
		}
		if err = ring.SetDirection(pfring.ReceiveAndTransmit); err != nil {
			return nil, err
		}
		if err = ring.SetSocketMode(pfring.ReadOnly); err != nil {
			return nil, err
		}
		if err = ring.SetCluster(p.cluster, pfring.ClusterPerFlow5Tuple); err != nil {
			return nil, err
		}
		if err = ring.Enable(); err != nil {
			return nil, err
		}
		p.rings = append(p.rings, ring)

		packetSource := gopacket.NewPacketSource(ring, layers.LinkTypeEthernet)
		res = append(res, packetSource)
	}
	return res, nil
}

func (p *pfRing) destroy() {
	for _, ring := range p.rings {
		ring.Close()
	}
}

var strategies = map[string]packetsCaptureStrategy{
	"pcap":   &native{},
	"pfring": &pfRing{cluster: 1234},
}

func getStrategyNames() []string {
	var keys []string
	for k := range strategies {
		keys = append(keys, k)
	}
	return keys
}
