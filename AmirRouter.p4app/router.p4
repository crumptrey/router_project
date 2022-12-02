/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define IP_PACKETS 0
#define ARP_PACKETS 1
#define CPU_PACKETS 2

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<8> key_t;
typedef bit<16> mcastGrp_t;
typedef bit<9> port_t;

typedef bit<32> PacketCounter_t;

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_ARP = 0x806;
const bit<16> TYPE_CPU_METADATA = 0x080a;

const port_t CPU_PORT           = 0x1;

const bit<16> ARP_OP_REQ        = 0x0001;
const bit<16> ARP_OP_REPLY      = 0x0002;

const bit<8> IP_PROT_ICMP = 0x01;
const bit<8> IP_PROT_OSPF = 0x59;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header cpu_metadata_t {
    bit<8> fromCpu;
    bit<16> origEtherType;
    bit<16> srcPort;
    bit<16> outPort;
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

header icmp_t {
    bit<8> type;
    bit<8> code;
    bit<16> hdrChecksum;
    bit<16> id;
    bit<16> seq;
}

header ospf_t {
    bit<8> version;
    bit<8> type;
    bit<16> totalLen;
    bit<32> routerID;
    bit<32> areaID;
    bit<16> chechsum;
    bit<16> auType;
    bit<64> authentication;
}

struct routing_metadata_t {
    ip4Addr_t nhop_ipv4;
}

struct metadata { 
    routing_metadata_t routing;
}

struct headers { 
    ethernet_t          ethernet;
    cpu_metadata_t      cpu_metadata;
    arp_t               arp;
    ipv4_t              ipv4;
    icmp_t              icmp;
    ospf_t              ospf;
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
            TYPE_IPV4: parse_ipv4;
            TYPE_ARP: parse_arp;
            TYPE_CPU_METADATA: parse_cpu;
            default: accept;
        }
    }

    state parse_cpu {
        packet.extract(hdr.cpu_metadata);
        transition select(hdr.cpu_metadata.origEtherType) {
            TYPE_IPV4: parse_ipv4;
            TYPE_ARP: parse_arp;
            default: accept;
        }
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROT_ICMP: parse_icmp;
            IP_PROT_OSPF: parse_ospf;
            default: accept;
        }
    }

    state parse_icmp {
        packet.extract(hdr.icmp);
        transition accept;
    }

    state parse_ospf {
        packet.extract(hdr.ospf);
        transition accept;
    }

}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply { 
         verify_checksum(hdr.ipv4.isValid(),
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
                hdr.ipv4.dstAddr
                },
                hdr.ipv4.hdrChecksum,
                HashAlgorithm.csum16);
    }
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    counter(4, CounterType.packets) c;
    
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action set_mgid(mcastGrp_t mgid) {
        standard_metadata.mcast_grp = mgid;
    }
    
    action update_ttl() {
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action increase_ttl() {
        hdr.ipv4.ttl = hdr.ipv4.ttl + 1;
    }

    action set_egr(port_t port) {
        standard_metadata.egress_spec = port;
    }

    action cpu_meta_encap() {
        hdr.cpu_metadata.setValid();
        hdr.cpu_metadata.origEtherType = hdr.ethernet.etherType;
        hdr.cpu_metadata.srcPort = (bit<16>)standard_metadata.ingress_port;
        hdr.cpu_metadata.outPort = 0;
        hdr.ethernet.etherType = TYPE_CPU_METADATA;
    }

    action cpu_meta_decap() {
        hdr.ethernet.etherType = hdr.cpu_metadata.origEtherType;
        hdr.cpu_metadata.setInvalid();
    }

    action send_to_cpu() {
        cpu_meta_encap();
        set_egr(CPU_PORT);
        c.count(CPU_PACKETS);
    }

    action set_dmac(macAddr_t dmac) {
        hdr.ethernet.dstAddr = dmac;
    }

    action set_nhop(port_t port, ip4Addr_t ipv4) {
        set_egr(port);
        if (ipv4 != 0) {
            meta.routing.nhop_ipv4 = ipv4;
        }
        else {
            meta.routing.nhop_ipv4 = hdr.ipv4.dstAddr;
        }
    }

    action hello_broadcast(ip4Addr_t ipv4) {
        meta.routing.nhop_ipv4 = ipv4;
    }

    table routing_table {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            set_nhop;
            hello_broadcast;
            NoAction;
            drop;
        }
        size = 256;
        default_action = NoAction();
    }

    table arp_table {
        key = {
            meta.routing.nhop_ipv4: exact;
        }
        actions = {
            set_mgid;
            set_dmac;
            NoAction;
            drop;
        }
        size = 64;
        default_action = NoAction();
    }

    table local_table {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            // send_to_cpu;
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
        default_action = NoAction();
    }

    apply {
        // Counters:
        if (hdr.arp.isValid()) {
            c.count(ARP_PACKETS);
        }
        if (hdr.ipv4.isValid()) {
            c.count(IP_PACKETS);
        }


        if (standard_metadata.ingress_port == CPU_PORT) {
            // if the output port is set by the controller -> Just forward the packet through that port
            if (hdr.cpu_metadata.outPort != 0) {
                set_egr((bit<9>)hdr.cpu_metadata.outPort);
                cpu_meta_decap();
                return;
            }
            cpu_meta_decap();
        }

        // Sending Arp packets to CPU, or forward it if it's from CPU
        if (hdr.arp.isValid()) {
            if (standard_metadata.ingress_port == CPU_PORT) {
                fwd_l2.apply();
                return;
            }
            else {
                send_to_cpu();
                return;
            }
        } 
        // Sending incoming OSPF packets directly to cpu for processing
        else if (hdr.ospf.isValid() && standard_metadata.ingress_port != CPU_PORT) {
            send_to_cpu();
            return;
        }
        // Handling IPv4 Packets
        else if (hdr.ipv4.isValid()) {
            // Drop in the case of checksum mismatch or 0 time-to-live
            if ((standard_metadata.checksum_error == 1 && standard_metadata.ingress_port != CPU_PORT) || hdr.ipv4.ttl == 0) {
                drop();
                return;
            } 
            else {
                update_ttl();
                // Sending local packets to CPU
                if (local_table.apply().hit) {
                    increase_ttl(); // To make up for the extra decrement
                    send_to_cpu();
                    return;
                }
                // Applying routing table and arp table
                if (routing_table.apply().hit) {
                    // Send the packet if arp entry exists
                    if (arp_table.apply().hit) {
                        return;
                    }
                    // Send to cpu if arp does not exist
                    else {
                        increase_ttl(); // To make up for the extra decrement
                        send_to_cpu();
                        return;
                    }
                }
                // Send to cpu if routing entry does not exist
                else {
                    increase_ttl(); // To make up for the extra decrement
                    send_to_cpu();
                    return;
                }
            }
        }
        // Send to CPU if not IPv4 or ARP
        else {
            send_to_cpu();
        }

    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    action set_smac(macAddr_t mac) {
        hdr.ethernet.srcAddr = mac;
    }
    
    // This table will set the src mac address when the packet is being forwarded out of the router
    table ports_mac_table {
        key = {
            standard_metadata.egress_port: exact;
        }

        actions = {
            set_smac;
            NoAction;
        }

        default_action = NoAction();
    }
    apply { 
        ports_mac_table.apply();
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
        packet.emit(hdr.icmp);
        packet.emit(hdr.ospf);
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
