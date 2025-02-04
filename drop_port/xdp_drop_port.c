#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>  // For bpf_htons/bpf_ntohs

#define ETH_P_IP 0x0800  // Define ETH_P_IP for IPv4

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, uint32_t);    // Source IP
    __type(value, uint16_t);  // Destination Port
} ip_port_map SEC(".maps");

SEC("xdp_drop_port")
int drop_packet(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
        return XDP_PASS;

    // Check for IPv4 (ETH_P_IP is defined here)
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // Parse IP header
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
        return XDP_PASS;

    if (ip->version != 4)
        return XDP_PASS;

    // Check for TCP
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    // Parse TCP header
    struct tcphdr *tcp = data + sizeof(*eth) + sizeof(*ip);
    if ((void *)tcp + sizeof(*tcp) > data_end)
        return XDP_PASS;

    // Get source IP and destination port
    uint32_t src_ip = ip->saddr;
    uint16_t dest_port = bpf_ntohs(tcp->dest);

    // Lookup IP in map
    uint16_t *target_port = bpf_map_lookup_elem(&ip_port_map, &src_ip);
    if (target_port && dest_port == *target_port) {
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

