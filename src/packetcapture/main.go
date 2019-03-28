package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
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
	//log.Println(packet)
}

func capturePackets(source *gopacket.PacketSource) {
	for packet := range source.Packets() {
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
	device := flag.String("device", "", "network interface name to capture")
	method := flag.String("method", "",
		fmt.Sprintf("capture method to use. options are: %s", strings.Join(getStrategyNames(), ", ")))
	flag.Parse()

	strategy, ok := strategies[*method]
	if !ok {
		log.Fatalf("no such capture method: %s", *method)
	}
	packetSources, err := strategy.Create(*device)
	if err != nil {
		log.Fatal(err)
	}
	cleanUpOnSigterm(strategy)

	for _, source := range packetSources {
		go capturePackets(source)
	}

	printStats(strategy)
}
