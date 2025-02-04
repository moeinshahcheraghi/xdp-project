package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// Structure for BPF Map Key-Value
type KeyValue struct {
	IP   uint32
	Port uint16
}

func main() {
	// Check command line arguments
	if len(os.Args) != 4 {
		log.Fatalf("Usage: %s <interface> <source_ip> <port>\n", os.Args[0])
	}

	iface := os.Args[1] // Interface
	ipStr := os.Args[2] // IP address
	portStr := os.Args[3] // Port

	// Convert IP to uint32
	ip := net.ParseIP(ipStr)
	if ip == nil {
		log.Fatalf("Invalid IP address: %s\n", ipStr)
	}
	ip = ip.To4()
	ipUint := binary.LittleEndian.Uint32(ip)

	// Convert port to uint16
	var port uint16
	fmt.Sscanf(portStr, "%d", &port)

	// Load the XDP program
	spec, err := ebpf.LoadCollectionSpec("xdp_drop_port.o")
	if err != nil {
		log.Fatalf("Failed to load eBPF program: %v", err)
	}

	// Create BPF map for storing IP and port
	objs := struct {
		XdpProg   *ebpf.Program `ebpf:"drop_packet"`
		IpPortMap *ebpf.Map     `ebpf:"ip_port_map"`
	}{}

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.XdpProg.Close()
	defer objs.IpPortMap.Close()

	// Add the IP and port to the BPF map
	err = objs.IpPortMap.Put(ipUint, port)
	if err != nil {
		log.Fatalf("Failed to add entry to BPF map: %v", err)
	}

	// Attach the XDP program to the interface
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProg,
		Interface: ifaceIndex(iface),
	})
	if err != nil {
		log.Fatalf("Failed to attach XDP: %v", err)
	}
	defer l.Close()

	fmt.Printf("✅ XDP program attached to %s. Blocking %s on port %d\n", iface, ipStr, port)

	// Handle graceful termination of the program
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig

	fmt.Println("\n🔻 Detaching XDP program...")
}

// Get the interface index by its name
func ifaceIndex(name string) int {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		log.Fatalf("Failed to get interface %s: %v", name, err)
	}
	return iface.Index
}

