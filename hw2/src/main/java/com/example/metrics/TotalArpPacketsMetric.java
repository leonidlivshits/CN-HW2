package com.example.metrics;

import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import java.util.concurrent.atomic.AtomicLong;

public class TotalArpPacketsMetric implements Metric {
    private final AtomicLong count = new AtomicLong(0);

    @Override
    public void onEthernetFrame(EthernetPacket eth) {}

    @Override
    public void onArpPacket(ArpPacket arp, EthernetPacket eth) {
        count.incrementAndGet();
    }

    @Override
    public String getName() {
        return "Всего ARP-пакетов";
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