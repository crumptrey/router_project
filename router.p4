/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

typedef bit<9>  port_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<16> mcastGrp_t;

const bit<32> NUM_PORT = 5;

const port_t CPU_PORT = 0x1;

const bit<16> ARP_OP_REQ = 0x0001;
const bit<16> ARP_OP_REPLY = 0x0002;

const bit<8> ICMP_PROTO = 0x01;
const bit<8> PWOSPF_PROTO = 0x59;

const bit<16> TYPE_ARP = 0x0806;
const bit<16> TYPE_CPU_METADATA = 0x080a;
const bit<16> TYPE_IPV4 = 0x0800;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header cpu_metadata_t {
    bit<8> fromCpu;
    bit<16> origEtherType;
    bit<16> srcPort;
    bit<16> dstPort;
}

header arp_t {
    bit<16> hwType;
    bit<16> protoType;
    bit<8> hwAddrLen;
    bit<8> protoAddrLen;
    bit<16> opcode;
    // assumes hardware type is ethernet and protocol is IP
    macAddr_t srcEth;
    ip4Addr_t srcIP;
    macAddr_t dstEth;
    ip4Addr_t dstIP;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

struct headers {
    ethernet_t        ethernet;
    cpu_metadata_t    cpu_metadata;
    arp_t             arp;
    ipv4_t            ipv4;
}
struct routing_meta_t {
    ip4Addr_t   ipv4_next_hop;
    macAddr_t   mac_next_hop;
}
struct metadata {
    routing_meta_t  routing;
}


parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_ARP: parse_arp;
            TYPE_CPU_METADATA: parse_cpu_metadata;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_cpu_metadata {
        packet.extract(hdr.cpu_metadata);
        transition select(hdr.cpu_metadata.origEtherType) {
            TYPE_ARP: parse_arp;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
      verify_checksum(
          hdr.ipv4.isValid(),
          {
            hdr.ipv4.version,
            hdr.ipv4.ihl,
            hdr.ipv4.diffserv,
            hdr.ipv4.totalLen,
            hdr.ipv4.identification,
            hdr.ipv4.flags,
            hdr.ipv4.fragOffset,
            hdr.ipv4.ttl,
            hdr.ipv4.protocol,
            hdr.ipv4.srcAddr,
            hdr.ipv4.dstAddr
          },
          hdr.ipv4.hdrChecksum,
          HashAlgorithm.csum16
        );
    }
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    // Counters
    counter(NUM_PORT, CounterType.packets) ip_packets;
    counter(NUM_PORT, CounterType.packets) arp_packets;
    counter(NUM_PORT, CounterType.packets) cpu_packets;
    counter(NUM_PORT, CounterType.packets) icmp_packets;
    counter(NUM_PORT, CounterType.packets) pwospf_packets;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action set_egr(port_t port) {
        standard_metadata.egress_spec = port;
    }

    action set_mgid(mcastGrp_t mgid) {
        standard_metadata.mcast_grp = mgid;
    }

    action cpu_meta_encap() {
        hdr.cpu_metadata.setValid();
        hdr.cpu_metadata.origEtherType = hdr.ethernet.etherType;
        hdr.cpu_metadata.srcPort = (bit<16>)standard_metadata.ingress_port;
        hdr.ethernet.etherType = TYPE_CPU_METADATA;
    }

    action cpu_meta_decap() {
        hdr.ethernet.etherType = hdr.cpu_metadata.origEtherType;
        hdr.cpu_metadata.setInvalid();
    }

    action send_to_cpu() {
        standard_metadata.egress_spec = CPU_PORT;
        cpu_meta_encap();
    }

    action ipv4_match(ip4Addr_t dstAddr, port_t port) {
        standard_metadata.egress_spec = port;
        if (dstAddr != 0 ){
            meta.routing.ipv4_next_hop = dstAddr;
        }
        else {
            meta.routing.ipv4_next_hop = hdr.ipv4.dstAddr;
        }
    }

    action arp_match(macAddr_t dstAddr) {
        meta.routing.mac_next_hop = dstAddr;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = meta.routing.mac_next_hop;
    }
    
    // Provide an ARP table that can store at least 64 entries. This will accept an IP address as a search key and will return the associated MAC address (if found). This table is modified by the software, which runs its own ARP protocol

    table arp_table {
        key = {
            meta.routing.ipv4_next_hop: exact;
        }
        actions = {
            arp_match;
            NoAction;
        }
        size = 64;
        default_action = NoAction();
    }

    table fwd_l2 {
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            set_egr;
            set_mgid;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }
    // Provide a routing table that can store IP address/prefix pairs with their associated port and next-hop IP address
    // Use the routing table to perform a longest prefix match on destination IP addresses and return the appropriate egress port and next-hop address

    table routing_table {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_match;
            NoAction;
            drop;
        }
        size = 1024;
        default_action = NoAction;
        // packets for which no matching entry is found in the routing table should be send to software
    }

    // Provide a "local IP address table". This will accept an IP address as a search key and will return a signal that indicates whether the corresponding address was found. This table is used to identify IP addresses that should be forwarded to the CPU
    table local_routing {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            send_to_cpu;
            NoAction;
        }
        size = 64;
        default_action = NoAction();
    }


    apply {
        if (standard_metadata.ingress_port == CPU_PORT) {
            if (hdr.cpu_metadata.dstPort != 0) {
                standard_metadata.egress_spec = (bit<9>)hdr.cpu_metadata.dstPort;
            }
            cpu_meta_decap();
        }
        if (hdr.arp.isValid()) {
            arp_packets.count((bit<32>) 1);
        }
        if (hdr.arp.isValid() && standard_metadata.ingress_port != CPU_PORT) { // Handling ARP in control-plane
            send_to_cpu();
        }

        else if (hdr.ipv4.isValid() && standard_metadata.checksum_error == 0){
            ip_packets.count((bit<32>) 1);
            // Verify that the TTL is valid 
            if (hdr.ipv4.ttl == 0) {
                drop();
            }
            else {
                // Look up the next-hop port and IP address in the route table
                // If it's not going to the CPU, look up MAC of next-hop
                if (!local_routing.apply().hit) {
                    routing_table.apply();
                }
                if (standard_metadata.egress_spec != CPU_PORT){
                    arp_table.apply();
                }
                // Decrement TTL
                hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
                if (hdr.ipv4.protocol == PWOSPF_PROTO){
                    pwospf_packets.count((bit<32>) 1);
                    if (standard_metadata.ingress_port != CPU_PORT) { // needed a way for received hello packets to get processed by controller
                        send_to_cpu();
                    }
                }
                if (hdr.ipv4.protocol == ICMP_PROTO) {
                    icmp_packets.count((bit<32>) 1);
                }
            }
        }
        else if (hdr.ethernet.isValid()) {
            fwd_l2.apply();
        }
        else { // Any packets that hardware cannot deal with should be forwarded to CPU
            send_to_cpu();
        }
        if (standard_metadata.egress_spec == CPU_PORT) {
            cpu_packets.count((bit<32>) 1);
        }

    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    action set_smac(macAddr_t mac) {
        hdr.ethernet.srcAddr = mac;
    }

    table mac_rewrite {

        key = {
            standard_metadata.egress_port: exact;
        }

        actions = {
            set_smac;
            NoAction;
        }
   }

    apply {
        mac_rewrite.apply();
    }
}

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
    apply {
	  update_checksum(
	      hdr.ipv4.isValid(),
              { hdr.ipv4.version,
			    hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr },
              hdr.ipv4.hdrChecksum,
              HashAlgorithm.csum16);
      }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.cpu_metadata);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
    }
}

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
