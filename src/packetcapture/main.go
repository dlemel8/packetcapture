package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

var packetsNum uint64

func printPPS() {
	before := atomic.LoadUint64(&packetsNum)
	time.Sleep(time.Second)
	after := atomic.LoadUint64(&packetsNum)
	fmt.Printf("pps: %d\n", after-before)
}

func processPacket(packet gopacket.Packet) {
	//fmt.Println(packet)
}

func capturePackets(source *gopacket.PacketSource) {
	for packet := range source.Packets() {
		atomic.AddUint64(&packetsNum, 1)
		processPacket(packet)
	}
}

func cleanUpOnSigterm(strategy *packetsCaptureStrategy) {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("got SIGTERM, cleanup and exit...")
		(*strategy).destroy()
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
	packetSources, err := strategy.create(*device)
	if err != nil {
		log.Fatal(err)
	}
	cleanUpOnSigterm(&strategy)

	for _, source := range packetSources {
		go capturePackets(source)
	}

	for {
		printPPS()
	}
}
