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
	"sync/atomic"
	"syscall"
	"time"
)

var packetsNum uint64

func printStats() {
	before := atomic.LoadUint64(&packetsNum)
	time.Sleep(time.Second)
	after := atomic.LoadUint64(&packetsNum)
	log.Printf("pps: %d, goroutine number: %d\n", after-before, runtime.NumGoroutine())
}

func processPacket(packet gopacket.Packet) {
	//log.Println(packet)
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
		log.Println("got SIGTERM, cleanup and exit...")
		(*strategy).Destroy()
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
	cleanUpOnSigterm(&strategy)

	for _, source := range packetSources {
		go capturePackets(source)
	}

	for {
		printStats()
	}
}
