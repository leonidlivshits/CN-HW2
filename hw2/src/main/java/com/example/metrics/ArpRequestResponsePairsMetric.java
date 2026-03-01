package com.example.metrics;

import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.namednumber.ArpOperation;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

public class ArpRequestResponsePairsMetric implements Metric {
    private final AtomicLong pairs = new AtomicLong(0);
    private final ConcurrentHashMap<String, Integer> pendingRequests = new ConcurrentHashMap<>();

    @Override
    public void onEthernetFrame(EthernetPacket eth) {}

    @Override
    public void onArpPacket(ArpPacket arp, EthernetPacket eth) {
        ArpOperation op = arp.getHeader().getOperation();
        String requestKey = arp.getHeader().getSrcProtocolAddr() + ":" + arp.getHeader().getDstProtocolAddr();
        String replyKey = arp.getHeader().getDstProtocolAddr() + ":" + arp.getHeader().getSrcProtocolAddr();

        if (op.equals(ArpOperation.REQUEST)) {
            pendingRequests.merge(requestKey, 1, Integer::sum);
        } else if (op.equals(ArpOperation.REPLY)) {
            Integer count = pendingRequests.get(replyKey);
            if (count != null && count > 0) {
                pairs.incrementAndGet();
                pendingRequests.merge(replyKey, -1, Integer::sum);
            }
        }
    }

    @Override
    public String getName() {
        return "Пар ARP-запрос/ответ";
    }

    @Override
    public String getValueAsString() {
        return String.valueOf(pairs.get());
    }

    @Override
    public void reset() {
        pairs.set(0);
        pendingRequests.clear();
    }
}