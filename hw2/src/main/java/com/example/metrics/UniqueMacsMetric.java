package com.example.metrics;

import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.util.MacAddress;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class UniqueMacsMetric implements Metric {
    private final Set<MacAddress> uniqueMacs = ConcurrentHashMap.newKeySet();

    @Override
    public void onEthernetFrame(EthernetPacket eth) {
        uniqueMacs.add(eth.getHeader().getSrcAddr());
        uniqueMacs.add(eth.getHeader().getDstAddr());
    }

    @Override
    public void onArpPacket(ArpPacket arp, EthernetPacket eth) {}

    @Override
    public String getName() {
        return "Уникальных mac адресов";
    }

    @Override
    public String getValueAsString() {
        return String.valueOf(uniqueMacs.size());
    }

    @Override
    public void reset() {
        uniqueMacs.clear();
    }
}