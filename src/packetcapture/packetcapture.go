package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pfring"
	"log"
	"os"
	"strconv"
	"time"
)

const (
	maxPacketSize             = 65536
	clusterDefaultRingsNum    = 4
	clusterRingsNumEnvVarName = "CLUSTER_RINGS_NUM"
)

type packetsCaptureStrategy interface {
	Create(device string) ([]*gopacket.PacketSource, error)
	Destroy()
}

type pcapStrategy struct {
	handle *pcap.Handle
}

func (n *pcapStrategy) Create(device string) ([]*gopacket.PacketSource, error) {
	var err error

	log.Println("creating pcap handler")

	n.handle, err = pcap.OpenLive(device, maxPacketSize, true, 30*time.Second)
	if err != nil {
		return nil, err
	}

	packetSource := gopacket.NewPacketSource(n.handle, n.handle.LinkType())
	return []*gopacket.PacketSource{packetSource}, nil
}

func (n *pcapStrategy) Destroy() {
	n.handle.Close()
}

type pfringStrategy struct {
	clusterId int
	rings     []*pfring.Ring
}

func (p *pfringStrategy) Create(device string) ([]*gopacket.PacketSource, error) {
	ringsNum := 1
	if p.clusterId > 0 {
		ringsNum = getNumOfRings()
	}
	log.Printf("creating %d rings\n", ringsNum)

	var res []*gopacket.PacketSource
	for i := 0; i < ringsNum; i++ {
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
		if p.clusterId > 0 {
			if err = ring.SetCluster(p.clusterId, pfring.ClusterPerFlow5Tuple); err != nil {
				return nil, err
			}
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

func (p *pfringStrategy) Destroy() {
	for _, ring := range p.rings {
		_ = ring.Disable()
	}
	for _, ring := range p.rings {
		ring.Close()
	}
}

func getNumOfRings() int {
	ringsNumStr, ok := os.LookupEnv(clusterRingsNumEnvVarName)
	if !ok {
		return clusterDefaultRingsNum
	}

	ringsNum, err := strconv.Atoi(ringsNumStr)
	if err != nil {
		return clusterDefaultRingsNum
	}

	return ringsNum
}

type afPacketStrategy struct {
	clusterId int
	handles   []*afpacket.TPacket
}

func (s *afPacketStrategy) Create(device string) ([]*gopacket.PacketSource, error) {
	ringsNum := 1
	if s.clusterId > 0 {
		ringsNum = getNumOfRings()
	}
	log.Printf("creating %d rings\n", ringsNum)

	var res []*gopacket.PacketSource
	for i := 0; i < ringsNum; i++ {
		handle, err := afpacket.NewTPacket(
			afpacket.OptInterface(device),
			afpacket.OptFrameSize(maxPacketSize),
			afpacket.OptTPacketVersion(afpacket.TPacketVersion3),
		)
		if err != nil {
			return nil, err
		}
		if s.clusterId > 0 {
			if err = handle.SetFanout(afpacket.FanoutHash, uint16(s.clusterId)); err != nil {
				return nil, err
			}
		}
		s.handles = append(s.handles, handle)

		packetSource := gopacket.NewPacketSource(handle, layers.LinkTypeEthernet)
		res = append(res, packetSource)
	}

	return res, nil
}

func (s *afPacketStrategy) Destroy() {
	for _, handle := range s.handles {
		handle.Close()
	}
}

var strategies = map[string]packetsCaptureStrategy{
	"pcap":            &pcapStrategy{},
	"pfring":          &pfringStrategy{},
	"pfring-cluster":  &pfringStrategy{clusterId: 1234},
	"afpacket":        &afPacketStrategy{},
	"afpacket-fanout": &afPacketStrategy{clusterId: 1234},
}

func getStrategyNames() []string {
	var keys []string
	for k := range strategies {
		keys = append(keys, k)
	}
	return keys
}
