package com.example.metrics;

import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;

public interface Metric {
    void onEthernetFrame(EthernetPacket eth);
    void onArpPacket(ArpPacket arp, EthernetPacket eth);
    String getName();
    String getValueAsString();
    default void reset() {}
}