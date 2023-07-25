/* Original named C_DUT. This script will vary depending on whether sf is defined,
 * so later there should be a reframer-forward-only version
 */

//t :: TSCClock(NOWAIT true)
//j :: JiffieClock()
h :: HTTPServer(PORT 8080)

StaticThreadSched(t 15, j 15, h 15);

elementclass MUXProcesser {
    input
        -> MarkMACHeader
        -> CheckIPHeader(OFFSET 14, CHECKSUM false)
//        -> SetTimestamp(PER_BATCH false)
        -> output;
};


elementclass PGWProcesser {
    input
        -> MarkMACHeader
        -> checkIp :: CheckIPHeader(OFFSET 14, DETAILS true, CHECKSUM false)
//        -> SetTimestamp(PER_BATCH false)
        -> output;
};

elementclass SF {

        sc1 :: Counter -> sf1 :: { [0] -> sf :: SFMaker(DELAY 64, DELAY_LAST 0, DELAY_HARD 0, TAKE_ALL 0, PROTO_COMPRESS 0, REORDER 0, PRIO DELAY, ALWAYSUP 0, MODEL SECOND, MAX_BURST 128, MAX_TX_BURST 32, VERBOSE 1, BYPASS_AFTER_FAIL 0, MAX_CAP 1000) -> StoreData(19,\<00>) -> output;}
sc2 :: Counter -> sf2 :: { [0] -> sf :: SFMaker(DELAY 64, DELAY_LAST 0, DELAY_HARD 0, TAKE_ALL 0, PROTO_COMPRESS 0, REORDER 0, PRIO DELAY, ALWAYSUP 0, MODEL SECOND, MAX_BURST 128, MAX_TX_BURST 32, VERBOSE 1, BYPASS_AFTER_FAIL 0, MAX_CAP 1000) -> StoreData(19,\<01>) -> output;}
sc3 :: Counter -> sf3 :: { [0] -> sf :: SFMaker(DELAY 64, DELAY_LAST 0, DELAY_HARD 0, TAKE_ALL 0, PROTO_COMPRESS 0, REORDER 0, PRIO DELAY, ALWAYSUP 0, MODEL SECOND, MAX_BURST 128, MAX_TX_BURST 32, VERBOSE 1, BYPASS_AFTER_FAIL 0, MAX_CAP 1000) -> StoreData(19,\<02>) -> output;}
sc4 :: Counter -> sf4 :: { [0] -> sf :: SFMaker(DELAY 64, DELAY_LAST 0, DELAY_HARD 0, TAKE_ALL 0, PROTO_COMPRESS 0, REORDER 0, PRIO DELAY, ALWAYSUP 0, MODEL SECOND, MAX_BURST 128, MAX_TX_BURST 32, VERBOSE 1, BYPASS_AFTER_FAIL 0, MAX_CAP 1000) -> StoreData(19,\<03>) -> output;}
sc5 :: Counter -> sf5 :: { [0] -> sf :: SFMaker(DELAY 64, DELAY_LAST 0, DELAY_HARD 0, TAKE_ALL 0, PROTO_COMPRESS 0, REORDER 0, PRIO DELAY, ALWAYSUP 0, MODEL SECOND, MAX_BURST 128, MAX_TX_BURST 32, VERBOSE 1, BYPASS_AFTER_FAIL 0, MAX_CAP 1000) -> StoreData(19,\<04>) -> output;}
sc6 :: Counter -> sf6 :: { [0] -> sf :: SFMaker(DELAY 64, DELAY_LAST 0, DELAY_HARD 0, TAKE_ALL 0, PROTO_COMPRESS 0, REORDER 0, PRIO DELAY, ALWAYSUP 0, MODEL SECOND, MAX_BURST 128, MAX_TX_BURST 32, VERBOSE 1, BYPASS_AFTER_FAIL 0, MAX_CAP 1000) -> StoreData(19,\<05>) -> output;}

    input[0]
        -> fcl:: Classifier(12/0800,-)
	
        -> Strip(14)
	-> ftrans::IPClassifier(tcp or udp,-)

        

        -> fc :: FlowIPManagerIMP(CAPACITY 2000000)
        -> frr :: ExactCPUSwitch();
	
        frr[0] -> sc1;
frr[1] -> sc2;
frr[2] -> sc3;
frr[3] -> sc4;
frr[4] -> sc5;
frr[5] -> sc6;
	
        fu ::  Unstrip(14);



        out :: Null //IPPrint("SFOUT", ACTIVE 0)
        -> [0];

        sf1 -> fu;
sf2 -> fu;
sf3 -> fu;
sf4 -> fu;
sf5 -> fu;
sf6 -> fu;

        fu->out;

        sf :: HandlerAggregate(ELEMENT sf1/sf,ELEMENT sf2/sf,ELEMENT sf3/sf,ELEMENT sf4/sf,ELEMENT sf5/sf,ELEMENT sf6/sf )

        fcl[1] -> Print(NONIP) -> Discard;
        ftrans[1] -> Unstrip(14) -> Discard;

}

elementclass SM {
    [0] -> [0];

    sf :: HandlerAggregate();
}


DPDKInfo(NB_MBUF 1000000, MBUF_SIZE 2176)

//From Clients
//DDIOTune(N_WAYS 2, DEV 0)
fromClientsCtr, fromClientsIpCtr :: Counter


fd0 :: FromDPDKDevice(0, PROMISC true, MINQUEUES 6, MAXTHREADS 6, RSS_AGGREGATE 1, VERBOSE 3, NDESC 256, TIMESTAMP false , PAUSE full)
    -> fromClientsCtr
    -> sf_avg :: AverageCounterIMP(IGNORE 1, MAX 2, THRESHOLD 10000 )
    -> cf0 :: Classifier(
         12/0806 20/0001,
         12/0806 20/0002,
        12/0800
//		-
    );

    cf0[0] -> arpresp0 :: ARPResponder(10.220.0.1 00:00:00:00:00:00, 10.221.0.5 00:00:00:00:00:00);
    cf0[2] -> fromClientsIpCtr
    -> pgwp:: PGWProcesser()

    -> bub :: BurstStats
    -> bsb :: BatchStats
    -> sf :: SF()
    -> bsa :: BatchStats
    -> bua :: BurstStats

//    -> L2LoadBalancer(None, LB_MODE hash_agg, NSERVER $MAXSRV)
//    -> StoreEtherAddress(ae:aa:aa:4a:c3:fc, OFFSET src)

//    -> avgP :: AverageCounterIMP()
    -> EtherRewrite(SRC ae:aa:aa:4a:c3:fc, DST 00:00:00:00:00:00)
    -> td1 :: ToDPDKDevice(1, VERBOSE 2, N_QUEUES 1, NDESC 1024, TCO true, BLOCKING true);
//    -> tdIN :: ToDump(/mnt/traces/mixed.pcap, SNAPLEN 128, FORCE_TS false, NANO true);

//   td1 :: ToDPDKDevice(1, VERBOSE 2, N_QUEUES 1, NDESC 1024, TCO true, BLOCKING true);
//From MUX
fd1 :: FromDPDKDevice(1, PROMISC true, MINQUEUES 2, MAXTHREADS 2, RSS_AGGREGATE 1, VERBOSE 3, NDESC 256, TIMESTAMP false , PAUSE full)

    -> sm_avg :: AverageCounterIMP(IGNORE 1, MAX 2, THRESHOLD 10000 )
    -> cf1 :: Classifier(
        12/0806 20/0001,
        12/0806 20/0002,
        12/0800
//		-
    );
	cf1[0] -> arpresp1 :: ARPResponder(10.221.0.1 ae:aa:aa:4a:c3:fc);


    cf1[2]
    -> bA :: BurstStats
    -> MUXProcesser()
    -> sm :: SM()
    -> bB :: BurstStats
//    -> avgM :: AverageCounterIMP()
//    -> arpq :: ARPQuerier(IP 10.220.0.1, ETH 00:00:00:00:00:00, CACHE true)
    -> EtherRewrite(SRC 00:00:00:00:00:00, DST 00:00:00:00:00:00)
    -> td0 :: ToDPDKDevice(0, VERBOSE 2, NDESC 1024, TCO true, BLOCKING true);

arpresp0[0] -> td0;
arpresp1[0] -> td1;


arpresp0[0] -> td0;

cf0[1] -> Discard; //[1]arpq;
cf1[1] -> Discard;

Script( TYPE ACTIVE,
        set tl 0,
        wait 5s,
//        write avg.reset,
        set s $(now),
        wait $(sub $(ceil $s) $s)s,
        label loop,
        set t $(now),

        print "KPGW-$t-RESULT-TQUEUED $(sf/sf.add queued)",

//        print "KMUX-$t-RESULT-TBWP $(avgP.link_rate)",
//        print "KMUX-$t-RESULT-TBWM $(avgM.link_rate)",
        set l $(add $(load)),
        set tl $(add $l $tl),
        print "KREF-$t-RESULT-TALOAD $l",
        print "KREF-$t-RESULT-TMLOAD $(max $(load))",
//        print "KMUX-$t-RESULT-TQUEUED $(sm/sm.add queued)",
        print $(load),
//        write avg.reset,
//        write avgM.reset,
//        write avgP.reset,
        wait 1s,
        goto loop
);


DriverManager(
        pause,
        set rx $(add $(fd0.hw_count) $(fd1.hw_count)),
        set tx $(add $(td0.count) $(td1.count)),
        set dropped $(sf/sf.add dropped),
        print "RESULT-FROM-CLIENTS-COUNT $(fromClientsCtr.count)",
        print "RESULT-IP-FROM-CLIENTS-COUNT $(fromClientsIpCtr.count)",

        print "RESULT-PGW_AVGTHROUGHPUT $(sf_avg.link_rate)",

        print "RESULT-MUX_AVGTHROUGHPUT $(sm_avg.link_rate)",
        print "RESULT-PGW_SF $(sf/sf.add superframes)",
        print "RESULT-PGW_SF_FLOWS $(sf/sf.avg superframe_flows_avg)",
        print "RESULT-PGW_SF_SIZE $(sf/sf.avg superframe_size_avg)",
        print "RESULT-PGW_REORDERED $(sf/sf.add reordered)",
        print "RESULT-PGW_COMPRESS $(sf/sf.avg compress_avg)",
        print "RESULT-PGW_BURSTS $(sf/sf.avg bursts_avg)",
        print "RESULT-PGW_PACKETS $(sf/sf.avg packets_avg)",
        print "RESULT-PGW_COUNT_1 $(sf/sc1.count)",
print "RESULT-PGW_COUNT_2 $(sf/sc2.count)",
print "RESULT-PGW_COUNT_3 $(sf/sc3.count)",
print "RESULT-PGW_COUNT_4 $(sf/sc4.count)",
print "RESULT-PGW_COUNT_5 $(sf/sc5.count)",
print "RESULT-PGW_COUNT_6 $(sf/sc6.count)",
        print "RESULT-PGW_BYPASS_1 $(sf/bp.count)",
print "RESULT-PGW_BYPASS_2 $(sf/bp.count)",
print "RESULT-PGW_BYPASS_3 $(sf/bp.count)",
print "RESULT-PGW_BYPASS_4 $(sf/bp.count)",
print "RESULT-PGW_BYPASS_5 $(sf/bp.count)",
print "RESULT-PGW_BYPASS_6 $(sf/bp.count)",
        print "RESULT-PGW_USELESSWAIT $(sf/sf.avg useless_wait_avg)",
        print "RESULT-PGW_DUMP $(pgwp/checkIp.drop_details)",
        print "RESULT-PGW_BSB $(bsb.average)",
        print "RESULT-PGW_BSA $(bsa.average)",
        print "RESULT-PGW_BUB $(bub.average)",
	print "RESULT-BUB_MDN $(bub.median)",
	    print "RESULT-BUB-DMP $(bub.dump)",
        print "RESULT-PGW_BUA $(bua.average)",

        print "RESULT-MUX_BUB $(bA.average)",
        print "RESULT-MUX_BUA $(bB.average)",
        print "RESULT-REF_RCV $rx",
        print "RESULT-REF_TRA $tx",
        print "RESULT-PGW_KILLED $dropped",
//        print "RESULT-PGW_DROPPED $(max 0 $(sub $rx $tx $dropped))",
        print "RESULT-REF_TXDROPPED $(add $(td0.dropped) $(td1.dropped))",
        print "RESULT-REF_HWDROPPED $(add $(fd0.hw_dropped) $(fd1.hw_dropped))",
        print "RESULT-PGW_MIDSIZE $(div $(fd0.hw_bytes) $(fd0.hw_count))",
        print "RESULT-MUX_MIDSIZE $(div $(fd1.hw_bytes) $(fd1.hw_count))",
        print "RESULT-REF-USEFUL-CYCLES "$(add $(useful_kcycles)),
        print "RESULT-REF-USEFUL-CYCLES-PP "$(div $(add $(useful_kcycles)) $(div $rx 1000)),
//        write agg.write_text_file -,
//        read b.dump,
        read fd0.xstats,
        read fd1.xstats,
	
	print "COUNTER-2-RESULT-COUNT $(fd0.count)",
	print "COUNTER-3-RESULT-COUNT $(td1.count)",
	print "COUNTER-6-RESULT-COUNT $(fd1.count)",
	print "COUNTER-7-RESULT-COUNT $(td0.count)",
	print "RESULT-NOMBUFS-DUT0 $(fd0.nombufs)",
	print "RESULT-NOMBUFS-DUT1 $(fd1.nombufs)"
        )
