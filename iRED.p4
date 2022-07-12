/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> IP_PROTO = 253;

const bit<32> MinTh = 280; // Min threshold for 64 packets of buffer size
const bit<32> MaxTh = 560; // Max threshold for 64 packets of buffer size


#define MAX_HOPS 10
#define PORTS 10

const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_NORMAL        = 0;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_INGRESS_CLONE = 1;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_EGRESS_CLONE  = 2;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_COALESCED     = 3;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_RECIRC        = 4;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_REPLICATION   = 5;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_RESUBMIT      = 6;


/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<48> macAddr_v;
typedef bit<32> ip4Addr_v;
typedef bit<9>  egressSpec_v;

header ethernet_h {
    macAddr_v dstAddr;
    macAddr_v srcAddr;
    bit<16>   etherType;
}

header ipv4_h {
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
    ip4Addr_v srcAddr;
    ip4Addr_v dstAddr;
}


struct queue_metadata_t {
    @field_list(0)
    bit<32> output_port;
}

struct metadata {
    queue_metadata_t    queue_metadata;
}

struct headers {
    ethernet_h         ethernet;
    ipv4_h             ipv4;
}



/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

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
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            0: accept;
            default: accept;
        }
    } 
}   


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    
    register<bit<1>> (PORTS) flagtoDrop_reg; // Register ON/OFF drop action
    counter(4, CounterType.packets) forwardingPkt; // Counter forwarding packets
    counter(4, CounterType.packets) dropPkt; // Counter packets dropped by RED
    counter(4, CounterType.packets) dropRecirc; // Counter recirculated
    
    
    // Action to drop recirculate pkts
    action drop() {
        dropRecirc.count(meta.queue_metadata.output_port);
        mark_to_drop(standard_metadata);
    }

    // Action to drop pkts
    action drop_count() {
        dropPkt.count((bit<32>)standard_metadata.egress_spec);
        mark_to_drop(standard_metadata);
    }
    
    action ipv4_forward(macAddr_v dstAddr, egressSpec_v port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        forwardingPkt.count((bit<32>)standard_metadata.egress_spec);
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    
    apply {

        if (standard_metadata.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_RECIRC) {
            flagtoDrop_reg.write(meta.queue_metadata.output_port,1); 
            drop();
        }
        else {

            ipv4_lpm.apply();
        
            bit<1> flag;
        
            flagtoDrop_reg.read(flag,(bit<32>)standard_metadata.egress_spec);

            if (flag == 1){            
                flagtoDrop_reg.write((bit<32>)standard_metadata.egress_spec,0);
                drop_count();
            }

        }
    }
}


/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

        register<bit<10>> (1) dp_r; // Register to save drop probability        
        register<bit<32>>(PORTS) oldQdepth_reg; //Register to save old queue depth           
        counter(4, CounterType.packets) recirc; // Counter recirculate pkts
        counter(4, CounterType.packets) cloneCount; // Counter clone pkts
        
        // Send again the packet through both pipelines
        action recirculate_packet(){
            recirculate_preserving_field_list(0);
            recirc.count(meta.queue_metadata.output_port);
        }

        action clonePacket(){
            clone_preserving_field_list(CloneType.E2E ,meta.queue_metadata.output_port,0);
            cloneCount.count(meta.queue_metadata.output_port);
        }

        apply {
            
            // Check IF is a clone pkt generated in the egress
            if (standard_metadata.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_EGRESS_CLONE) {
                meta.queue_metadata.output_port = (bit<32>)standard_metadata.egress_port;
                recirculate_packet();
            } 
            else {

                bit<32> qdepth = (bit<32>)standard_metadata.enq_qdepth; // Get queue depth after TM
            
                bit<32> oldQdepth; //Old Qdepth  
                        
                oldQdepth_reg.read(oldQdepth, (bit<32>)standard_metadata.egress_port); // Read avg_queue register and save in oldQdepth
                oldQdepth_reg.write((bit<32>)standard_metadata.egress_port, qdepth);
            
                // WRED -> avg_WRED = o * (1 - 2^-n) + c * (2^-n)
                // where n is the user-configurable exponential weight factor, 
                // o is the old average and c is the current queue size. 
                // The previous average is more important for high values of n. Peaks and lows in 
                // queue size are smoothed by a high value. For low values of n, the average queue 
                // size is close to the current queue size.
                // We use n = 1. This makes the equation read as follows: New average = (Old_average * (1- 0.5)) + (Current_Q_depth * 0.5)
                // https://www.ccexpert.us/traffic-shaping-2/random-early-detection-red-1.html

                bit<32> new_avg = oldQdepth*5 + qdepth*5 ; //multiplied by 10;                     

                if (new_avg >= MinTh && new_avg <= MaxTh) {

                    bit<10> drop_random_temp;
                    dp_r.read(drop_random_temp,0);
                            
                    bit<10> a = 1;
                    bit<10> drop_prob = a + 1;
                    dp_r.write(0,drop_prob);
                            
                    bit<10> rand_val;
                    random(rand_val, 0, 511);
                            
                    if (drop_prob > rand_val){
                        meta.queue_metadata.output_port = (bit<32>)standard_metadata.egress_port;
                        clonePacket();
                    }
                }
                        
                if (new_avg > MaxTh) {
                    meta.queue_metadata.output_port = (bit<32>)standard_metadata.egress_port;
                    clonePacket();
                }

            }             
                 
        }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
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

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);                
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
