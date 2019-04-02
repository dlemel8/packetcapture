package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pfring"
	"log"
	"time"
)

const (
	maxPacketSizeInBytes = 1 << 16
	clusterId            = 1234
)

type PacketDataSource interface {
	gopacket.PacketDataSource
	gopacket.ZeroCopyPacketDataSource
}

type packetsCaptureStrategy interface {
	Create(device string, numberOfRings int) ([]PacketDataSource, error)
	Destroy()
	PacketStats() (received uint64, dropped uint64)
}

type pcapStrategy struct {
	handle *pcap.Handle
}

func (n *pcapStrategy) Create(device string, numberOfRings int) ([]PacketDataSource, error) {
	if numberOfRings > 1 {
		log.Println("WARNING: pcap not support cluster mode, ignoring number of rings parameter")
	}

	var err error
	n.handle, err = pcap.OpenLive(device, maxPacketSizeInBytes, true, 30*time.Second)
	if err != nil {
		return nil, err
	}

	return []PacketDataSource{n.handle}, nil
}

func (n *pcapStrategy) Destroy() {
	n.handle.Close()
}

func (n *pcapStrategy) PacketStats() (received uint64, dropped uint64) {
	stats, err := n.handle.Stats()
	if err != nil {
		return
	}

	if stats.PacketsReceived > 0 {
		received += uint64(stats.PacketsReceived)
	}

	if stats.PacketsDropped > 0 {
		dropped += uint64(stats.PacketsDropped)
	}
	return
}

type pfringStrategy struct {
	rings []*pfring.Ring
}

func (p *pfringStrategy) Create(device string, numberOfRings int) ([]PacketDataSource, error) {
	var res []PacketDataSource
	for i := 0; i < numberOfRings; i++ {
		ring, err := pfring.NewRing(device, maxPacketSizeInBytes, pfring.FlagPromisc)
		if err != nil {
			return nil, err
		}
		if err = ring.SetDirection(pfring.ReceiveAndTransmit); err != nil {
			return nil, err
		}
		if err = ring.SetSocketMode(pfring.ReadOnly); err != nil {
			return nil, err
		}
		if numberOfRings > 1 {
			if err = ring.SetCluster(clusterId, pfring.ClusterPerFlow5Tuple); err != nil {
				return nil, err
			}
		}
		if err = ring.Enable(); err != nil {
			return nil, err
		}
		p.rings = append(p.rings, ring)
		res = append(res, ring)
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

func (p *pfringStrategy) PacketStats() (received uint64, dropped uint64) {
	for _, ring := range p.rings {
		stats, err := ring.Stats()
		if err != nil {
			continue
		}
		received += stats.Received
		dropped += stats.Dropped
	}
	return
}

type afPacketStrategy struct {
	handles []*afpacket.TPacket
}

func (s *afPacketStrategy) Create(device string, numberOfRings int) ([]PacketDataSource, error) {
	var res []PacketDataSource
	for i := 0; i < numberOfRings; i++ {
		handle, err := afpacket.NewTPacket(
			afpacket.OptInterface(device),
			afpacket.OptFrameSize(maxPacketSizeInBytes),
			afpacket.OptTPacketVersion(afpacket.TPacketVersion3),
		)
		if err != nil {
			return nil, err
		}
		if numberOfRings > 1 {
			if err = handle.SetFanout(afpacket.FanoutHash, uint16(clusterId)); err != nil {
				return nil, err
			}
		}
		s.handles = append(s.handles, handle)
		res = append(res, handle)
	}

	return res, nil
}

func (s *afPacketStrategy) Destroy() {
	for _, handle := range s.handles {
		handle.Close()
	}
}

func (s *afPacketStrategy) PacketStats() (received uint64, dropped uint64) {
	for _, handle := range s.handles {
		_, stats, err := handle.SocketStats()
		if err != nil {
			continue
		}
		received += uint64(stats.Packets())
		dropped += uint64(stats.Drops())
	}
	return
}

var strategies = map[string]packetsCaptureStrategy{
	"pcap":     &pcapStrategy{},
	"pfring":   &pfringStrategy{},
	"afpacket": &afPacketStrategy{},
}

func getStrategyNames() []string {
	var keys []string
	for k := range strategies {
		keys = append(keys, k)
	}
	return keys
}
