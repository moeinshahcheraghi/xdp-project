package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// BPF key structure (aligned to 8 bytes)
type KeyValue struct {
	IP   uint32
	Port uint16
	_    uint16 // Padding to match eBPF struct alignment
}

func main() {
	if len(os.Args) < 4 {
		log.Fatalf("Usage: %s <interface> <source_ip> <port1> [port2] [port3] ...\n", os.Args[0])
	}

	iface := os.Args[1]
	ipStr := os.Args[2]
	portStrs := os.Args[3:]

	ip := net.ParseIP(ipStr)
	if ip == nil {
		log.Fatalf("Invalid IP address: %s\n", ipStr)
	}
	ip = ip.To4()
	ipUint := binary.LittleEndian.Uint32(ip)

	var ports []uint16
	for _, p := range portStrs {
		portNum, err := strconv.Atoi(p)
		if err != nil || portNum < 1 || portNum > 65535 {
			log.Fatalf("Invalid port: %s\n", p)
		}
		ports = append(ports, uint16(portNum))
	}

	spec, err := ebpf.LoadCollectionSpec("xdp_drop_port.o")
	if err != nil {
		log.Fatalf("Failed to load eBPF program: %v", err)
	}

	objs := struct {
		XdpProg   *ebpf.Program `ebpf:"drop_packet"`
		IpPortMap *ebpf.Map     `ebpf:"ip_port_map"`
	}{}

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.XdpProg.Close()
	defer objs.IpPortMap.Close()

	for _, port := range ports {
		key := KeyValue{IP: ipUint, Port: port}
		value := uint8(1) 

		err = objs.IpPortMap.Put(&key, value)
		if err != nil {
			log.Fatalf("Failed to add entry to BPF map: %v", err)
		}
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProg,
		Interface: ifaceIndex(iface),
	})
	if err != nil {
		log.Fatalf("Failed to attach XDP: %v", err)
	}
	defer l.Close()

	fmt.Printf("✅ XDP program attached to %s. Blocking %s on ports %v\n", iface, ipStr, ports)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig

	fmt.Println("\n🔻 Detaching XDP program...")
}

func ifaceIndex(name string) int {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		log.Fatalf("Failed to get interface %s: %v", name, err)
	}
	return iface.Index
}

