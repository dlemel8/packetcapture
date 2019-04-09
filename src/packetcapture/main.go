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

func printStats(strategy packetsCaptureStrategy, exit <-chan bool) {
	var receivedBefore uint64 = 0

	for {
		select {
		case <-exit:
			return
		default:
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

func capturePackets(source gopacket.PacketDataSource, exit <-chan bool) {
	packetSource := gopacket.NewPacketSource(source, layers.LinkTypeEthernet)
	packetSource.DecodeOptions = gopacket.NoCopy

	for {
		select {
		case <-exit:
			return
		default:
			packet, err := packetSource.NextPacket()
			if err != nil {
				continue
			}
			go processPacket(packet)
		}
	}
}

func capturePacketsZeroCopy(source gopacket.ZeroCopyPacketDataSource, exit <-chan bool) {
	for {
		select {
		case <-exit:
			return
		default:
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
	defer strategy.Destroy()

	exitCh := make(chan bool)
	for _, source := range packetDataSources {
		if *zeroCopy {
			go capturePacketsZeroCopy(source, exitCh)
		} else {
			go capturePackets(source, exitCh)
		}

	}
	go printStats(strategy, exitCh)
	defer close(exitCh) // notify all goroutines at once

	signalCh := make(chan os.Signal)
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)
	<-signalCh
	signal.Reset(syscall.SIGINT, syscall.SIGTERM)
	signal.Stop(signalCh)
	log.Println("got signal, cleanup and exit...")
}
