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

func main() {
	if len(os.Args) < 4 {
		log.Fatalf("Usage: %s <interface> <source_ip/CIDR> <port1> [port2] [port3] ...\n", os.Args[0])
	}

	iface := os.Args[1]
	cidrStr := os.Args[2]
	portStrs := os.Args[3:]

	// Parse the CIDR block
	_, ipNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		log.Fatalf("Invalid CIDR block: %s\n", cidrStr)
	}

	// Ensure IPv4
	ipNet.IP = ipNet.IP.To4()
	if ipNet.IP == nil {
		log.Fatalf("Only IPv4 addresses are supported: %s\n", cidrStr)
	}

	// Calculate prefix length
	cidrBits, _ := ipNet.Mask.Size()

	// Parse ports
	var ports []uint16
	for _, p := range portStrs {
		portNum, err := strconv.Atoi(p)
		if err != nil || portNum < 1 || portNum > 65535 {
			log.Fatalf("Invalid port: %s\n", p)
		}
		ports = append(ports, uint16(portNum))
	}

	// Load eBPF program
	spec, err := ebpf.LoadCollectionSpec("xdp_drop_port.o")
	if err != nil {
		log.Fatalf("Failed to load eBPF program: %v", err)
	}

	// Prepare eBPF objects
	objs := struct {
		XdpProg   *ebpf.Program `ebpf:"drop_packet"`
		IpPortMap *ebpf.Map     `ebpf:"ip_port_map"`
	}{}

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.XdpProg.Close()
	defer objs.IpPortMap.Close()

	// Convert network IP to uint32 in network byte order (big-endian)
	ipUint := binary.BigEndian.Uint32(ipNet.IP)

	// Insert entries into the BPF map
	for _, port := range ports {
		key := make([]byte, 16)
		// Prefixlen: CIDR bits + 16 bits for port
		binary.NativeEndian.PutUint32(key[0:4], uint32(cidrBits+16))
		// Port in host byte order
		binary.NativeEndian.PutUint16(key[4:6], port)
		// IP in network byte order (big-endian)
		binary.BigEndian.PutUint32(key[6:10], ipUint)
		// Pad with zeros
		for i := 10; i < 16; i++ {
			key[i] = 0
		}

		// Insert into map
		if err := objs.IpPortMap.Put(key, uint8(1)); err != nil {
			log.Fatalf("Failed to add entry to BPF map: %v", err)
		}
	}

	// Attach XDP program
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProg,
		Interface: ifaceIndex(iface),
	})
	if err != nil {
		log.Fatalf("Failed to attach XDP: %v", err)
	}
	defer l.Close()

	fmt.Printf("✅ XDP program attached to %s. Blocking %s on ports %v\n", iface, cidrStr, ports)

	// Wait for interrupt
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

