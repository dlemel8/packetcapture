package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"log"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"
)

func printStats(strategy packetsCaptureStrategy) {
	var receivedBefore uint64 = 0

	for {
		received, dropped := strategy.PacketStats()
		pps := received - receivedBefore
		packetLoss := 0.0
		if received > 0 || dropped > 0 {
			packetLoss = float64(dropped) / float64(received+dropped) * 100
		}
		log.Printf("pps: %d, packet loss: %2f%%, goroutine number: %d\n", pps, packetLoss, runtime.NumGoroutine())
		receivedBefore = received
		time.Sleep(time.Second)
	}
}

func processPacket(packet gopacket.Packet) {
	//if eth := packet.LinkLayer(); eth != nil {
	//	srcMac := eth.LinkFlow().Src()
	//}
	//if ip := packet.NetworkLayer(); ip != nil {
	//	srcIp, dstIp := ip.NetworkFlow().Endpoints()
	//}
	//if trans := packet.TransportLayer(); trans != nil {
	//	srcPort, dstPort := trans.TransportFlow().Endpoints()
	//}
}

func capturePackets(source gopacket.PacketDataSource) {
	packetSource := gopacket.NewPacketSource(source, layers.LinkTypeEthernet)
	packetSource.DecodeOptions = gopacket.NoCopy
	for packet := range packetSource.Packets() {
		go processPacket(packet)
	}
}

func capturePacketsZeroCopy(source gopacket.ZeroCopyPacketDataSource) {
	for {
		data, ci, err := source.ZeroCopyReadPacketData()
		if err != nil {
			continue
		}
		packet := gopacket.NewPacket(data, layers.LinkTypeEthernet, gopacket.NoCopy)
		m := packet.Metadata()
		m.CaptureInfo = ci
		m.Truncated = m.Truncated || ci.CaptureLength < ci.Length
		processPacket(packet)
	}
}

func cleanUpOnSigterm(strategy packetsCaptureStrategy) {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		log.Println("got SIGTERM, cleanup and exit...")
		strategy.Destroy()
		os.Exit(1)
	}()
}

func main() {
	device := flag.String("d", "", "network interface name to capture")
	strategyName := flag.String("s", "",
		fmt.Sprintf("capture strategy to use. options are: %s", strings.Join(getStrategyNames(), ", ")))
	numberOfRings := flag.Int("n", 1, "number of rings to use in cluster mode, if available")
	zeroCopy := flag.Bool("zc", false, "don't copy packet to user space to process it (default false)")
	bpfFilter := flag.String("f", "", "bpf filter (optional)")
	flag.Parse()

	strategy, ok := strategies[*strategyName]
	if !ok {
		flag.Usage()
		os.Exit(1)
	}
	packetDataSources, err := strategy.Create(*device, *numberOfRings, *bpfFilter)
	if err != nil {
		log.Fatal(err)
	}
	cleanUpOnSigterm(strategy)

	for _, source := range packetDataSources {
		if *zeroCopy {
			go capturePacketsZeroCopy(source)
		} else {
			go capturePackets(source)
		}

	}

	printStats(strategy)
}
