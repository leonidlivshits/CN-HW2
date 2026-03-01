package com.example;

import org.pcap4j.packet.Packet;

public interface PacketProcessor {
    void processPacket(Packet packet);
}