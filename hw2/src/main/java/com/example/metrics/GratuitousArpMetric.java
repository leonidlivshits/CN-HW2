package com.example.metrics;

import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.namednumber.ArpOperation;

import java.util.concurrent.atomic.AtomicLong;

public class GratuitousArpMetric implements Metric {
    private final AtomicLong count = new AtomicLong(0);

    @Override
    public void onEthernetFrame(EthernetPacket eth) {}

    @Override
    public void onArpPacket(ArpPacket arp, EthernetPacket eth) {
        if (arp.getHeader().getOperation().equals(ArpOperation.REQUEST) &&
                arp.getHeader().getSrcProtocolAddr().equals(arp.getHeader().getDstProtocolAddr()) &&
                !arp.getHeader().getSrcProtocolAddr().toString().equals("0.0.0.0")) {
            count.incrementAndGet();
        }
    }

    @Override
    public String getName() {
        return "Gratuitous ARP запросов";
    }

    @Override
    public String getValueAsString() {
        return String.valueOf(count.get());
    }

    @Override
    public void reset() {
        count.set(0);
    }
}