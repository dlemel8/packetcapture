package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"log"
	"strings"
	"sync/atomic"
	"time"
)

var packetsNum uint64

func printPPS() {
	for {
		before := atomic.LoadUint64(&packetsNum)
		time.Sleep(time.Second)
		after := atomic.LoadUint64(&packetsNum)
		fmt.Printf("pps: %d\n", after - before)
	}
}

func processPacket(packet gopacket.Packet) {
	//fmt.Println(packet)
}


func main() {
	device := flag.String("device", "", "network interface name to capture")
	method := flag.String("method", "",
		fmt.Sprintf("capture method to use. options are %s", strings.Join(getStrategyNames(), ", ")))
	flag.Parse()

	go printPPS()

	strategy, ok := strategies[*method]
	if !ok {
		log.Fatalf("no such capture method: %s", *method)
	}

	packetSource, err := strategy.create(*device)
	if err != nil {
		log.Fatal(err)
	}
	for packet := range packetSource.Packets() {
		atomic.AddUint64(&packetsNum, 1)
		processPacket(packet)
	}
}
