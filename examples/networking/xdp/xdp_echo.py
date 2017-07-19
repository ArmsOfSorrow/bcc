#!/usr/bin/env python
#
# xdp_echo.py       Retransmit each packet back to sender.
#
# based on:
#
# xdp_drop_count.py Drop incoming packets on XDP layer and count for which
#                   protocol type
#
# Copyright (c) 2016 PLUMgrid
# Copyright (c) 2016 Jan Ruth
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF
import pyroute2
import time
import sys

flags = 0
def usage():
    print("Usage: {0} [-S] <ifdev>".format(sys.argv[0]))
    print("       -S: use skb mode\n")
    print("e.g.: {0} eth0\n".format(sys.argv[0]))
    exit(1)

if len(sys.argv) < 2 or len(sys.argv) > 3:
    usage()

if len(sys.argv) == 2:
    device = sys.argv[1]

if len(sys.argv) == 3:
    if "-S" in sys.argv:
        # XDP_FLAGS_SKB_MODE
        flags |= 2 << 0

    if "-S" == sys.argv[1]:
        device = sys.argv[2]
    else:
        device = sys.argv[1]

mode = BPF.XDP
#mode = BPF.SCHED_CLS

if mode == BPF.XDP:
#    ret = "XDP_DROP"
    ret = "XDP_TX"
    ctxtype = "xdp_md"
else:
    ret = "TC_ACT_SHOT"
    ctxtype = "__sk_buff"

# load BPF program
b = BPF(text = """
#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>


BPF_TABLE("percpu_array", uint32_t, long, dropcnt, 256);

static inline int parse_ipv4(void *data, u64 nh_off, void *data_end) {
    struct iphdr *iph = data + nh_off;

    if ((void*)&iph[1] > data_end)
        return 0;
    return iph->protocol;
}

static inline int parse_ipv6(void *data, u64 nh_off, void *data_end) {
    struct ipv6hdr *ip6h = data + nh_off;

    if ((void*)&ip6h[1] > data_end)
        return 0;
    return ip6h->nexthdr;
}

static inline void switch_src_dst_mac(struct ethhdr *hdr)
{
    uint8_t tmp[6];
    tmp[0] = hdr->h_dest[0];
    tmp[1] = hdr->h_dest[1];
    tmp[2] = hdr->h_dest[2];
    tmp[3] = hdr->h_dest[3];
    tmp[4] = hdr->h_dest[4];
    tmp[5] = hdr->h_dest[5];

    //write src into dst
    hdr->h_dest[0] = hdr->h_source[0];
    hdr->h_dest[1] = hdr->h_source[1];
    hdr->h_dest[2] = hdr->h_source[2];
    hdr->h_dest[3] = hdr->h_source[3];
    hdr->h_dest[4] = hdr->h_source[4];
    hdr->h_dest[5] = hdr->h_source[5];

    hdr->h_source[0] = hdr->h_dest[0];
    hdr->h_source[1] = hdr->h_dest[1];
    hdr->h_source[2] = hdr->h_dest[2];
    hdr->h_source[3] = hdr->h_dest[3];
    hdr->h_source[4] = hdr->h_dest[4];
    hdr->h_source[5] = hdr->h_dest[5];
}

int xdp_prog1(struct CTXTYPE *ctx) {

    //data and data_end come from xdp_md -> packet data range pointers
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;

    struct ethhdr *eth = data;

    int rc = RETURNCODE; // let pass XDP_PASS or redirect to tx via XDP_TX
    long *value;
    uint16_t h_proto;

    //next header offset?
    uint64_t nh_off = 0;
    uint32_t index = 0;

    //I guess so, since we're getting the size of the ethernet header here
    //so the next one should start at this offset
    nh_off = sizeof(*eth);

    if (data + nh_off  > data_end)
        return XDP_DROP;

    h_proto = eth->h_proto;

    //actually, I think we don't even need to parse IP headers here.
    //just rewrite the mac and it should be good, moongen sends garbage IPs too
    
    /*if (h_proto == htons(ETH_P_IP))
        index = parse_ipv4(data, nh_off, data_end);
    else if (h_proto == htons(ETH_P_IPV6))
       index = parse_ipv6(data, nh_off, data_end);
    else
        index = 0;*/

    switch_src_dst_mac(eth);

    value = dropcnt.lookup(&index);
    if (value)
        *value += 1;

    return rc;
}
""", cflags=["-w", "-DRETURNCODE=%s" % ret, "-DCTXTYPE=%s" % ctxtype])

fn = b.load_func("xdp_prog1", mode)

if mode == BPF.XDP:
    b.attach_xdp(device, fn, flags)
else:
    ip = pyroute2.IPRoute()
    ipdb = pyroute2.IPDB(nl=ip)
    idx = ipdb.interfaces[device].index
    ip.tc("add", "clsact", idx)
    ip.tc("add-filter", "bpf", idx, ":1", fd=fn.fd, name=fn.name,
          parent="ffff:fff2", classid=1, direct_action=True)

dropcnt = b.get_table("dropcnt")
prev = [0] * 256
print("Printing drops per IP protocol-number, hit CTRL+C to stop")
while 1:
    try:
        for k in dropcnt.keys():
            val = dropcnt.sum(k).value
            i = k.value
            if val:
                delta = val - prev[i]
                prev[i] = val
                print("{}: {} pkt/s".format(i, delta))
        time.sleep(1)
    except KeyboardInterrupt:
        print("Removing filter from device")
        break;

if mode == BPF.XDP:
    b.remove_xdp(device)
else:
    ip.tc("del", "clsact", idx)
    ipdb.release()
