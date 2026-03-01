package com.example;

import org.pcap4j.core.PacketListener;
import org.pcap4j.packet.Packet;

import java.util.ArrayList;
import java.util.List;

public class PacketHandler implements PacketListener {
    private final List<PacketProcessor> processors = new ArrayList<>();

    public void addProcessor(PacketProcessor processor) {
        processors.add(processor);
    }

    @Override
    public void gotPacket(Packet packet) {
        for (PacketProcessor p : processors) {
            p.processPacket(packet);
        }
    }
}