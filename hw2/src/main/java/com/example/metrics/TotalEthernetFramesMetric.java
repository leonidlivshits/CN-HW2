package com.example.metrics;

import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import java.util.concurrent.atomic.AtomicLong;

public class TotalEthernetFramesMetric implements Metric {
    private final AtomicLong count = new AtomicLong(0);

    @Override
    public void onEthernetFrame(EthernetPacket eth) {
        count.incrementAndGet();
    }

    @Override
    public void onArpPacket(ArpPacket arp, EthernetPacket eth) {}

    @Override
    public String getName() {
        return "Всего Ethernet фреймов";
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