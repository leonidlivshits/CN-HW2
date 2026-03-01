package com.example;

import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;

public class StatisticsUpdater implements PacketProcessor {
    private final Statistics statistics;

    public StatisticsUpdater(Statistics statistics) {
        this.statistics = statistics;
    }

    @Override
    public void processPacket(Packet packet) {
        EthernetPacket eth = packet.get(EthernetPacket.class);
        if (eth != null) {
            statistics.updateEthernetFrame(eth);
        }
        ArpPacket arp = packet.get(ArpPacket.class);
        if (arp != null) {
            statistics.updateArpPacket(arp, eth);
        }
    }
}