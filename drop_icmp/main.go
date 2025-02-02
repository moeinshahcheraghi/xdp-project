package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Usage: %s <interface>", os.Args[0])
	}
	iface := os.Args[1] // Interface ro az arg migire

	// Load compiled eBPF program
	spec, err := ebpf.LoadCollectionSpec("xdp_drop_icmp.o")
	if err != nil {
		log.Fatalf("Failed to load eBPF program: %v", err)
	}

	// Load program from spec
	obj := struct {
		DropICMP *ebpf.Program `ebpf:"drop_icmp"`
	}{}
	if err := spec.LoadAndAssign(&obj, nil); err != nil {
		log.Fatalf("Failed to assign eBPF program: %v", err)
	}

	// Attach XDP program to network interface
	ifIndex := ifaceIndex(iface)
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   obj.DropICMP,
		Interface: ifIndex,
	})
	if err != nil {
		log.Fatalf("Failed to attach XDP program to %s: %v", iface, err)
	}
	defer l.Close()

	fmt.Printf("✅ XDP program attached to %s (index %d)\n", iface, ifIndex)

	// Handle CTRL+C for cleanup
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	<-ctx.Done() // Wait for CTRL+C
	fmt.Println("\n⏳ Detaching XDP program...")
	stop()
	l.Close()
	fmt.Println("✅ XDP program detached. Exiting.")
}

// Helper function to get interface index
func ifaceIndex(name string) int {
	links, err := net.Interfaces()
	if err != nil {
		log.Fatalf("Failed to list interfaces: %v", err)
	}
	for _, link := range links {
		if link.Name == name {
			return link.Index
		}
	}
	log.Fatalf("❌ Interface %s not found", name)
	return -1
}

