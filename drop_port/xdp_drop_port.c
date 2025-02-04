#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800

struct ip_port_key {
    __u32 ip;
    __u16 port;
    __u16 __pad;  // Ensure 8-byte alignment
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, struct ip_port_key);
    __type(value, __u8);
} ip_port_map SEC(".maps");

SEC("xdp_drop_port")
int drop_packet(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
        return XDP_PASS;

    if (ip->version != 4)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
    if ((void *)tcp + sizeof(*tcp) > data_end)
        return XDP_PASS;

    struct ip_port_key key = {
        .ip = ip->saddr,
        .port = bpf_ntohs(tcp->dest),
    };

    __u8 *value = bpf_map_lookup_elem(&ip_port_map, &key);
    if (value) {
        bpf_printk("Dropping packet: src_ip=%u, dest_port=%u", key.ip, key.port);
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

