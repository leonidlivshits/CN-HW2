package com.example.metrics;

import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.util.MacAddress;
import java.util.concurrent.atomic.AtomicLong;

public class ArpBroadcastMetric implements Metric {
    private final AtomicLong count = new AtomicLong(0);

    @Override
    public void onEthernetFrame(EthernetPacket eth) {}

    @Override
    public void onArpPacket(ArpPacket arp, EthernetPacket eth) {
        if (eth != null && MacAddress.ETHER_BROADCAST_ADDRESS.equals(eth.getHeader().getDstAddr())) {
            count.incrementAndGet();
        }
    }

    @Override
    public String getName() {
        return "Из них широковещательных ARP";
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