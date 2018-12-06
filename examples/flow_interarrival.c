#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <stdlib.h>
#include "ebpf_switch.h"

#define MAX_ENTRIES 1<<8
#define NB_TIMESLOTS 8
#define BPF_MAP_TYPE_CFILTER 3

const uint64_t WINDOW_TIME = 10000000ULL; // Refresh interval:
                                          // 10 ms in nanoseconds

// The windows is divided into 32 buckets,
// each represented by an individual cuckoo filter
const uint64_t SLOT_TIME = WINDOW_TIME>>3;

struct ip_5tuple {
    uint32_t sip;
    uint32_t dip;
    uint16_t sport;
    uint16_t dport;
    uint8_t proto;
} __attribute__((packed));

struct globals {
    uint8_t      curr_slot;
    uint64_t     slot_timestamp;
    uint64_t     window_timestamp;
};

struct bpf_map_def SEC("maps") global_vals = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(struct globals),
    .max_entries = 1,
};

struct bpf_map_def SEC("maps") inports = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = 6, // MAC address is the key
    .value_size = sizeof(uint32_t),
    .max_entries = 256,
};

struct bpf_map_def SEC("maps") slot0 = {
    .type = BPF_MAP_TYPE_CFILTER,
    .key_size = sizeof(struct ip_5tuple), 
    .value_size = sizeof(uint32_t),
    .max_entries = MAX_ENTRIES,
};

struct bpf_map_def SEC("maps") slot1 = {
    .type = BPF_MAP_TYPE_CFILTER,
    .key_size = sizeof(struct ip_5tuple), 
    .value_size = sizeof(uint32_t),
    .max_entries = MAX_ENTRIES,
};

struct bpf_map_def SEC("maps") slot2 = {
    .type = BPF_MAP_TYPE_CFILTER,
    .key_size = sizeof(struct ip_5tuple), 
    .value_size = sizeof(uint32_t),
    .max_entries = MAX_ENTRIES,
};

struct bpf_map_def SEC("maps") slot3 = {
    .type = BPF_MAP_TYPE_CFILTER,
    .key_size = sizeof(struct ip_5tuple), 
    .value_size = sizeof(uint32_t),
    .max_entries = MAX_ENTRIES,
};

struct bpf_map_def SEC("maps") slot4 = {
    .type = BPF_MAP_TYPE_CFILTER,
    .key_size = sizeof(struct ip_5tuple), 
    .value_size = sizeof(uint32_t),
    .max_entries = MAX_ENTRIES,
};

struct bpf_map_def SEC("maps") slot5 = {
    .type = BPF_MAP_TYPE_CFILTER,
    .key_size = sizeof(struct ip_5tuple), 
    .value_size = sizeof(uint32_t),
    .max_entries = MAX_ENTRIES,
};

struct bpf_map_def SEC("maps") slot6 = {
    .type = BPF_MAP_TYPE_CFILTER,
    .key_size = sizeof(struct ip_5tuple), 
    .value_size = sizeof(uint32_t),
    .max_entries = MAX_ENTRIES,
};

struct bpf_map_def SEC("maps") slot7 = {
    .type = BPF_MAP_TYPE_CFILTER,
    .key_size = sizeof(struct ip_5tuple), 
    .value_size = sizeof(uint32_t),
    .max_entries = MAX_ENTRIES,
};

static inline int parse_5tuple(struct packet *pkt, struct ip_5tuple *t){
    struct iphdr    *ip;
    struct tcphdr   *tcp;
    struct udphdr   *udp;
    struct icmphdr  *icmp;

    if (pkt->eth.h_proto == 0x0008) {

        ip = (struct iphdr *)(((uint8_t *)&pkt->eth) + ETH_HLEN);
        t->sip = ip->saddr;
        t->dip = ip->daddr;

        switch(ip->protocol){
            case IPPROTO_TCP:
                tcp = (struct tcphdr *)(((uint32_t *)ip) + ip->tot_len);
                t->sport = tcp->source;
                t->dport = tcp->dest;
                t->proto = IPPROTO_TCP;
                break;
            case IPPROTO_UDP:
                udp = (struct udphdr *)(((uint32_t *)ip) + ip->tot_len);
                t->sport = udp->source;
                t->dport = udp->dest;
                t->proto = IPPROTO_UDP;
                break;
            case IPPROTO_ICMP:
                icmp = (struct icmphdr *)(((uint32_t *)ip) + ip->tot_len);
                t->sport = 0;
                t->dport = 0;
                t->proto = IPPROTO_ICMP;
                break;
            default:
                t->sport = 0;
                t->dport = 0;
                t->proto = 0;
                return -1;
        }
    }

    return 0;
}

static inline struct bpf_map_def* get_slot(uint8_t index){

    switch(index){
        case 0:
            return &slot0;
            break;
        case 1:
            return &slot1;
            break;
        case 2:
            return &slot2;
            break;
        case 3:
            return &slot3;
            break;
        case 4:
            return &slot4;
            break;
        case 5:
            return &slot5;
            break;
        case 6:
            return &slot6;
            break;
        case 7:
            return &slot7;
            break;
    }

    return NULL;
}

// struct bpf_map_def *slots[] = {&slot0,&slot1,&slot2,&slot3,&slot4,&slot5,&slot6,&slot7};


uint64_t prog(struct packet *pkt)
{
    size_t zero = 0;
    struct globals *vals;
    struct ip_5tuple t = {0,0,0,0,0};
    struct bpf_map_def *time_slot;
    uint64_t currenttime;
    uint64_t window_delta;
    uint64_t slot_delta;
    
    bpf_map_lookup_elem(&global_vals,&zero,&vals);
    
    currenttime = ((uint64_t)pkt->metadata.sec << 32) | pkt->metadata.nsec;
    window_delta = currenttime - vals->window_timestamp;
    slot_delta = currenttime - vals->slot_timestamp;

    if(slot_delta >= SLOT_TIME){
        vals->curr_slot = (vals->curr_slot + 1)%NB_TIMESLOTS;
        vals->slot_timestamp = currenttime;
        // bpf_debug("SLOT!!");
        // bpf_notify(1,&delta,sizeof(delta));
    }

    if(window_delta >= WINDOW_TIME){
        // Save the structure to file and clear entries
        bpf_map_save(&slot0);
        bpf_map_save(&slot1);
        bpf_map_save(&slot2);
        bpf_map_save(&slot3);
        bpf_map_save(&slot4);
        bpf_map_save(&slot5);
        bpf_map_save(&slot6);
        bpf_map_save(&slot7);
        vals->window_timestamp = currenttime;
        // bpf_debug("WINDOW!!");
    }


    // bpf_notify(1,&delta,sizeof(delta));

    parse_5tuple(pkt,&t);

    // Mark flow as seen
    if(t.proto != 0){
        // time_slot = slots[vals->curr_slot];
        time_slot = get_slot(vals->curr_slot);

        bpf_map_update_elem(time_slot,&t,0,0);
        // bpf_notify(4,&time_slot,sizeof(time_slot));
        // bpf_notify(3,&vals->curr_slot,sizeof(vals->curr_slot));
    }

    // ================== Learning Switch ==================
    uint32_t *out_port;

    // if the source is not a broadcast or multicast
    if ((pkt->eth.h_source[0] & 1) == 0) {
        // Update the port associated with the packet
        bpf_map_update_elem(&inports, pkt->eth.h_source, &pkt->metadata.in_port, 0);
    }

    // Flood if the destination is broadcast or multicast
    if (pkt->eth.h_dest[0] & 1) {
        return FLOOD;
    }

    // Lookup the output port
    if (bpf_map_lookup_elem(&inports, pkt->eth.h_dest, &out_port) == -1) {
        // If no entry was found flood
        return FLOOD;
    }

    return *out_port;
}
char _license[] SEC("license") = "GPL";