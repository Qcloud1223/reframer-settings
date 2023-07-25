/* Originally named chain.config, the non-http version */

define(
    $iface       0,
    $rxQueues     8,
    $ndesc       256,
    $txQueueSize 1024,
    $burst       32,
    $pause       full,
    $promisc     true,
    $mtu         9000,
    $rssAgg      1,
    $lro         ${LRO},
    $verbose     99,
    $retIface	 0
);
require(library ../router-100.click);

AddressInfo(
    lan_interface 127.0.0.1 00:00:00:00:00:00,
    wan_interface 10.1.0.128     00:0c:29:64:de:ab
);

elementclass Pipeline {$th |
    input[0] -> p::Pipeliner(BLOCKING true) -> [0]output;
    StaticThreadSched(p $th);
}

elementclass NatModule {
    // IP Classifier before the NAT
    ip_rw_l :: IPClassifier(proto tcp, proto udp, -);

    // NAT logic
    rwpattern :: IPRewriterPatterns(NAT lan_interface 1024-65535 - -);
    tcp_rw :: TCPRewriter(pattern NAT 0 0);
    udp_rw :: UDPRewriter(pattern NAT 0 0);
   
    input[0] -> ip_rw_l

    ip_rw_l[0] -> [0]tcp_rw;
    ip_rw_l[1] -> [0]udp_rw;
    ip_rw_l[2] -> Discard;

    tcp_rw[0] -> output;
    udp_rw[0] -> output;
}

elementclass MergeSF {

    sc1 :: Counter -> FlowIPManagerIMP(CAPACITY 2000000) -> sf1 :: { [0] -> sf :: SFMaker(DELAY 64, DELAY_LAST 0, DELAY_HARD 0, TAKE_ALL $TAKEALL, PROTO_COMPRESS 0, REORDER 0, PRIO $PRIO, ALWAYSUP 0, MODEL SECOND, MAX_BURST 128, MAX_TX_BURST 32, VERBOSE 1, MAX_CAP 1000) -> output;}
sc2 :: Counter -> FlowIPManagerIMP(CAPACITY 2000000) -> sf2 :: { [0] -> sf :: SFMaker(DELAY 64, DELAY_LAST 0, DELAY_HARD 0, TAKE_ALL $TAKEALL, PROTO_COMPRESS 0, REORDER 0, PRIO $PRIO, ALWAYSUP 0, MODEL SECOND, MAX_BURST 128, MAX_TX_BURST 32, VERBOSE 1, MAX_CAP 1000) -> output;}
sc3 :: Counter -> FlowIPManagerIMP(CAPACITY 2000000) -> sf3 :: { [0] -> sf :: SFMaker(DELAY 64, DELAY_LAST 0, DELAY_HARD 0, TAKE_ALL $TAKEALL, PROTO_COMPRESS 0, REORDER 0, PRIO $PRIO, ALWAYSUP 0, MODEL SECOND, MAX_BURST 128, MAX_TX_BURST 32, VERBOSE 1, MAX_CAP 1000) -> output;}
sc4 :: Counter -> FlowIPManagerIMP(CAPACITY 2000000) -> sf4 :: { [0] -> sf :: SFMaker(DELAY 64, DELAY_LAST 0, DELAY_HARD 0, TAKE_ALL $TAKEALL, PROTO_COMPRESS 0, REORDER 0, PRIO $PRIO, ALWAYSUP 0, MODEL SECOND, MAX_BURST 128, MAX_TX_BURST 32, VERBOSE 1, MAX_CAP 1000) -> output;}
sc5 :: Counter -> FlowIPManagerIMP(CAPACITY 2000000) -> sf5 :: { [0] -> sf :: SFMaker(DELAY 64, DELAY_LAST 0, DELAY_HARD 0, TAKE_ALL $TAKEALL, PROTO_COMPRESS 0, REORDER 0, PRIO $PRIO, ALWAYSUP 0, MODEL SECOND, MAX_BURST 128, MAX_TX_BURST 32, VERBOSE 1, MAX_CAP 1000) -> output;}
sc6 :: Counter -> FlowIPManagerIMP(CAPACITY 2000000) -> sf6 :: { [0] -> sf :: SFMaker(DELAY 64, DELAY_LAST 0, DELAY_HARD 0, TAKE_ALL $TAKEALL, PROTO_COMPRESS 0, REORDER 0, PRIO $PRIO, ALWAYSUP 0, MODEL SECOND, MAX_BURST 128, MAX_TX_BURST 32, VERBOSE 1, MAX_CAP 1000) -> output;}
sc7 :: Counter -> FlowIPManagerIMP(CAPACITY 2000000) -> sf7 :: { [0] -> sf :: SFMaker(DELAY 64, DELAY_LAST 0, DELAY_HARD 0, TAKE_ALL $TAKEALL, PROTO_COMPRESS 0, REORDER 0, PRIO $PRIO, ALWAYSUP 0, MODEL SECOND, MAX_BURST 128, MAX_TX_BURST 32, VERBOSE 1, MAX_CAP 1000) -> output;}
sc8 :: Counter -> FlowIPManagerIMP(CAPACITY 2000000) -> sf8 :: { [0] -> sf :: SFMaker(DELAY 64, DELAY_LAST 0, DELAY_HARD 0, TAKE_ALL $TAKEALL, PROTO_COMPRESS 0, REORDER 0, PRIO $PRIO, ALWAYSUP 0, MODEL SECOND, MAX_BURST 128, MAX_TX_BURST 32, VERBOSE 1, MAX_CAP 1000) -> output;}

    input[0] -> Strip(14)
    -> frr :: ExactCPUSwitch();

    frr[0] -> sc1;
frr[1] -> sc2;
frr[2] -> sc3;
frr[3] -> sc4;
frr[4] -> sc5;
frr[5] -> sc6;
frr[6] -> sc7;
frr[7] -> sc8;

    fu ::  Unstrip(14);

    sf1 -> fu;
sf2 -> fu;
sf3 -> fu;
sf4 -> fu;
sf5 -> fu;
sf6 -> fu;
sf7 -> fu;
sf8 -> fu;

    fu -> [0]output;

    sf :: HandlerAggregate(ELEMENT sf1/sf,ELEMENT sf2/sf,ELEMENT sf3/sf,ELEMENT sf4/sf,ELEMENT sf5/sf,ELEMENT sf6/sf,ELEMENT sf7/sf,ELEMENT sf8/sf )
}


// Module's I/O
nicIn0  :: FromDPDKDevice($iface, N_QUEUES $rxQueues, NDESC $ndesc, BURST $burst, PROMISC $promisc, MTU $mtu, PAUSE $pause, LRO $lro, RSS_AGGREGATE $rssAgg, VERBOSE $verbose);
//	 
//	);
	
nicOut0 :: ToDPDKDevice($retIface, IQUEUE $txQueueSize, BURST $burst, BLOCKING false);

// Classifier to split ARP from IP
class_left :: Classifier(12/0806 20/0001,  // ARP query
                         12/0806 20/0002,  // ARP response
                         12/0800);         // IPv4

set_count :: SetCycleCount;
cycle_counter :: CycleCountAccum;

// Static ARP using direct EtherEncap
//arpq_left :: ARPQuerier(lan_interface) -> cycle_counter -> nicOut0;
arpq_left :: EtherEncap(ETHERTYPE 0x0800, SRC 00:00:00:00:00:00, DST ae:aa:aa:1b:bf:33)
    -> cycle_counter
    -> nicOut0;
//    -> Discard;


pipeline :: Null //FlowIPManager
            -> avg :: AverageCounterIMP(IGNORE 1, MAX 2, THRESHOLD 10000 )
//              -> FlowIPManagerIMP(CAPACITY 2000000)  -> fc :: FlowCounter
            -> arpq_left;

// Firewall logic
ipFilter :: IPFilter(CACHING true, file /home/hamid/workspace/reframer/rules-msft-merged);
ipFilter[0-1]   -> NatModule() -> pipeline;

ipFilter[2]
    -> dropped :: AverageCounterIMP
    -> IPPrint(FW-DROPPED:, LENGTH true, TTL true, ACTIVE true)
    -> arpq_left;


// Wiring
nicIn0 -> set_count -> class_left;

class_left[0] -> Print("ARP REQUEST") -> ARPResponder(lan_interface) -> nicOut0;
//class_left[1] -> Print("ARP REPLY") -> [1]arpq_left;
class_left[1] -> Print("ARP REPLY") -> Discard;
class_left[2]
    -> CheckIPHeader(OFFSET 14, CHECKSUM false)
    -> tcpudpcls :: IPClassifier (tcp or udp, -)
    -> counter :: AverageCounterIMP
    ->  b :: BurstStats
    
    ->  bsa :: BurstStats
      -> FlowIPManagerIMP(CAPACITY 2000000)  -> fc :: FlowCounter
//    -> AggregateLength
//    -> agg :: AggregateStats(MAX 65536)
    -> aggLen :: AggregateLength
    -> avgBatchCnt :: AverageBatchCounter(LENGTH_STATS true)
    -> pms :: PacketMemStats
    -> Strip(14)
     -> Router()
    
    -> ipFilter;

noudptcp:: Counter;
tcpudpcls[1] -> noudptcp -> Discard;


Script(TYPE ACTIVE, label s, print "EVENT DUT_READY", print "TDUT-$(now)-RESULT-DUT_BW $(counter.link_rate)", write counter.reset, wait 1, goto s, print "");

DriverManager(
    wait,
    read nicIn0.xstats,
    print "======================================================",

    print "                  RESULT-DUT-FLOWS "$(fc.count),
    print "             RESULT-DUT-THROUGHPUT "$(avg.link_rate),
    print "                RESULT-DUT-RCVTIME "$(avg.time),
    print "    RESULT-DUT-NO-UDP-OR-TCP-COUNT "$(noudptcp.count),
    print "          RESULT-DUT-ALIGNED-COUNT "$(pms.aligned_pkts),
    print "        RESULT-DUT-UNALIGNED-COUNT "$(pms.unaligned_pkts),
    print "RESULT-DUT-ALIGNED-UNALIGNED-COUNT "$(pms.total_pkts),
    print "               RESULT-DUT-TD-COUNT "$(nicOut0.count),
    print "               RESULT-DUT-HW-COUNT "$(nicIn0.hw_count),
    print "             RESULT-DUT-HW-DROPPED "$(nicIn0.hw_dropped),
    print "               RESULT-DUT-SW-COUNT "$(nicIn0.count),
//    print "               RESULT-DUT-CYCLES "$(cycle_counter.cycles),
//    print "            RESULT-DUT-CYCLES-PP "$(cycle_counter.cycles_pp),
    print "          RESULT-DUT-ALIGNED-RATIO "$(pms.aligned_pkts_ratio),
    print "        RESULT-DUT-UNALIGNED-RATIO "$(pms.unaligned_pkts_ratio),
    print "          RESULT-TOT-AVG-FRAME-LEN "$(avgBatchCnt.average_frame_len_total),
    print "             RESULT-AVG-BATCH-SIZE "$(avgBatchCnt.average_total),
    print "              RESULT-USEFUL-CYCLES "$(add $(useful_kcycles)),
    print "           RESULT-USEFUL-CYCLES-PP "$(div $(add $(useful_kcycles)) $(nicIn0.count)),
    print "                RESULT-SRV_INBURST "$(b.avg),
    print "                RESULT-NFS_INBURST "$(bsa.avg),
    print "======================================================",
    print "COUNTER-4-RESULT-COUNT $(nicIn0.count)",
    print "COUNTER-5-RESULT-COUNT $(nicOut0.count)",
);
//--------------------------- End of Chain  --------------------------

//-------------------------------- Beginning of Chain  -------------------------------

// Q: remove sudo and wait
// %chain:script@dut sudo=true waitfor=GEN_DONE
