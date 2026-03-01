package com.example;

import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.Packet;

public class ArpPrinter implements PacketProcessor {
    private boolean enabled = false;

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    @Override
    public void processPacket(Packet packet) {
        if (!enabled) return;
        ArpPacket arp = packet.get(ArpPacket.class);
        if (arp != null) {
            System.out.println("ARP пакет");
            System.out.println("Operation: " + arp.getHeader().getOperation());
            System.out.println("Sender MAC: " + arp.getHeader().getSrcHardwareAddr());
            System.out.println("Sender IP: " + arp.getHeader().getSrcProtocolAddr());
            System.out.println("Target MAC: " + arp.getHeader().getDstHardwareAddr());
            System.out.println("Target IP: " + arp.getHeader().getDstProtocolAddr());
            System.out.println();
        }
    }
}