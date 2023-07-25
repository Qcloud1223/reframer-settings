/* Originally named PKTGEN_CONFIG */

d :: DPDKInfo(12000000)

define($bout 1)
define($INsrcmac 00:00:00:00:00:00)
define($RAW_INsrcmac 000000000000)

define($INdstmac 00:00:00:00:00:00)
define($RAW_INdstmac 000000000000)

define($ignore 1)
define($replay_count 1)
define($port 0)
define($quick true)
define($txverbose 99)
define($rxverbose 99)

elementclass MyNull { [0-1]=>[0- 1 ]; };

//JiffieClock()
fdIN0 :: FromIPSummaryDump(/mnt/traces/caida.pcap-1, TIMES $replay_count, TIMING true, TIMESTAMP true, ZERO false, BURST 32, STOP true);
fdIN1 :: FromIPSummaryDump(/mnt/traces/caida.pcap-2, TIMES $replay_count, TIMING true, TIMESTAMP true, ZERO false, BURST 32, STOP true);

tdIN ::
 
    ToDPDKDevice($port, BLOCKING true, BURST $bout, VERBOSE $txverbose, IQUEUE $bout, NDESC 0, IPCO true )

elementclass NoTimestampDiff { $a, $b, $c, $d |
input -> output;
Idle->[1]output;
}

elementclass Numberise { $magic |
    input-> Strip(14)
     -> check :: MarkIPHeader  -> nPacket :: NumberPacket(42) -> StoreData(40, $magic)
    -> ResetIPChecksum() -> Unstrip(14) -> output
}

ender :: Script(TYPE PASSIVE,
                print "Limit of 100000000 reached",
                stop,
                stop);
 rr :: MyNull; 

fdIN0-> limit0   :: Counter(COUNT_CALL 50000000 ender.run) -> [0]rr
fdIN1-> limit1   :: Counter(COUNT_CALL 50000000 ender.run) -> [1]rr

elementclass Generator { $magic |
input
 
  -> MarkMACHeader
-> EnsureDPDKBuffer
-> EtherEncap(0x0800, $INsrcmac, $INdstmac)

-> Pad 
  -> Numberise($magic)
  -> avgSIN :: AverageCounter(IGNORE $ignore)
  -> rt :: RecordTimestamp(N 20000000, OFFSET 56)
  -> output;
}

gen0 :: Generator(\<5700>) -> tdIN;
gen1 :: Generator(\<5701>) -> tdIN;
StaticThreadSched(fdIN0 0/1 )
StaticThreadSched(fdIN1 0/2 )
rr[0] -> gen0;
rr[1] -> gen1;






receiveIN :: FromDPDKDevice($port, VERBOSE $rxverbose, MAC $INsrcmac, PROMISC true, PAUSE full, NDESC 0, MAXTHREADS 4,NUMA false)

elementclass Receiver { $mac, $dir |
    input[0]
 -> c :: Classifier(-, 0/ffffffffffff)
    -> Strip(14)
    -> CheckIPHeader(CHECKSUM false)

    -> magic :: Classifier( 40/5700, 40/5701,  -);

    c[1] //Not for this computer or broadcasts
    -> Discard;

magic[0] -> tsd0 :: TimestampDiff(gen0/rt, OFFSET 42, N 20000000, SAMPLE 10 ) -> Unstrip(14) ->  avg0 :: AverageCounterMP(IGNORE $ignore) -> Discard;  tsd0[1] -> Print('WARNING: Untimestamped packet on thread 0', 64) -> Discard;
magic[1] -> tsd1 :: TimestampDiff(gen1/rt, OFFSET 42, N 20000000, SAMPLE 10 ) -> Unstrip(14) ->  avg1 :: AverageCounterMP(IGNORE $ignore) -> Discard;  tsd1[1] -> Print('WARNING: Untimestamped packet on thread 1', 64) -> Discard;


avg :: HandlerAggregate( ELEMENT avg0,ELEMENT avg1 );

    magic[2]
    -> Unstrip(14)
    -> Print("WARNING: Unknown magic / untimestamped packet", -1)
    -> Discard;


}

/*Script(TYPE ACTIVE,
    label loop,
    read load,
    wait 1s,
    goto loop)*/

ig :: Script(TYPE ACTIVE,
    goto end $(eq 0 0),
    set s $(now),
    set lastcount 0,
    set lastbytes 0,
    set lastsent 0,
    set lastdrop 0,
    set last $s,
    set indexA 0,
    set indexB 0,
    set indexC 0,
    set indexD 0,
    label loop,
    wait 0s,
    set n $(now), 
    set t $(sub $n $s),
    set elapsed $(sub $n $last),
    set last $n,

                set count $(RIN/avg.add count),
                set sent $(avgSIN.add count),
                set bytes $(RIN/avg.add byte_count),
                print "IG-$t-RESULT-IGCOUNT $(sub $count $lastcount)",
                print "IG-$t-RESULT-IGSENT $(sub $sent $lastsent)",
                set drop $(sub $sent $count),
                print "IG-$t-RESULT-IGDROPPED $(sub $drop $lastdrop)",
                set lastdrop $drop,
                print "IG-$t-RESULT-IGTHROUGHPUT $(div $(mul $(add $(mul $(sub $count $lastcount) 24) $(sub $bytes $lastbytes)) 8) $elapsed)",
                goto next $(eq 1 0),
//                print "IG-$t-RESULT-ILAT01 $(RIN/tsd0.perc01 $indexA)",
//                print "IG-$t-RESULT-ILAT50 $(RIN/tsd0.median $indexA)",
                print "IG-$t-RESULT-ILATENCY $(RIN/tsd0.average $indexA)",
//                print "IG-$t-RESULT-ILAT99 $(RIN/tsd0.perc99 $indexA)",
                set indexA $(RIN/tsd0.index),
                label next,
                set lastcount $count,
                set lastsent $sent,
                set lastbytes $bytes,
    goto loop,
    label end
)

StaticThreadSched(ig 15);

receiveIN -> RIN :: Receiver($RAW_INsrcmac,"IN");

tsd :: HandlerAggregate( ELEMENT RIN/tsd0,ELEMENT RIN/tsd1 );

avgSIN :: HandlerAggregate( ELEMENT gen0/avgSIN,ELEMENT gen1/avgSIN );

dm :: DriverManager(  print "Waiting 2 seconds before launching generation...",
                wait 2s,

                print "EVENT GEN_BEGIN",
                print "Starting gen...",
//                write fdIN.active true,
                print "Starting timer wait...",
                set starttime $(now),
                wait 3,
//                write fdIN.active 0,
                set stoptime $(now),
                print "EVENT GEN_DONE",
                wait 1s,
                read receiveIN.hw_count,
                read receiveIN.count,
                read receiveIN.xstats,
                goto alatval $(eq 1 0),
                goto adump $(eq 0 0),
/*                print "Dumping latency samples to /tmp/latency.csv",
                print >/tmp/latency.csv $(RIN/tsdA.dump_list),
                print >>/tmp/latency.csv $(RIN/tsdB.dump_list),
                print >>/tmp/latency.csv $(RIN/tsdC.dump_list),
                print >>/tmp/latency.csv $(RIN/tsdD.dump_list),*/
                label adump,

                print "RESULT-LATENCY $(tsd.avg average)",
                print "RESULT-LAT00 $(tsd.avg min)",
                print "RESULT-LAT01 $(tsd.avg perc01)",
                print "RESULT-LAT50 $(tsd.avg median)",
                print "RESULT-LAT95 $(tsd.avg perc95)",
                print "RESULT-LAT99 $(tsd.avg perc99)",
                print "RESULT-LAT100 $(tsd.avg max)",
                goto alatval $(eq 0 0),
                set i 0,
                set step 1,
                label perc,
                print "CDFLATVAL-$(RIN/tsd.avg perc $i)-RESULT-CDFLATPC $(div $i 100.0)",
                set i $(add $i $step),
                set step $(if $(ge $i 99) 0.1 1),
                goto perc $(le $i 100.0),
                label alatval,
                print "RESULT-TESTTIME $(sub $stoptime $starttime)",
                print "RESULT-RCVTIME $(RIN/avg.avg time)",
                print "RESULT-THROUGHPUT $(RIN/avg.add link_rate)",
                set sent $(avgSIN.add count),
                set count $(RIN/avg.add count),
                set bytes $(RIN/avg.add byte_count),
                print "RESULT-COUNT $count",
                print "RESULT-BYTES $bytes",
                print "RESULT-SENT $sent",
                print "RESULT-DROPPED $(sub $sent $count)",
                print "RESULT-DROPPEDPC $(div $(sub $sent $count) $sent)",
//                print "RESULT-DROPPEDPS $(div $(sub $sent $count) $(RIN/avg.avg time))",
                print "RESULT-TX $(avgSIN.add link_rate)",
                print "RESULT-PPS $(RIN/avg.add rate)",
                stop);

StaticThreadSched(dm 15);
