package com.example.metrics;

import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.util.MacAddress;
import java.util.concurrent.atomic.AtomicLong;

public class TrafficWithRouterMetric implements Metric {
    private final AtomicLong bytes = new AtomicLong(0);
    private MacAddress routerMac = null;

    public void setRouterMac(MacAddress routerMac) {
        this.routerMac = routerMac;
    }

    @Override
    public void onEthernetFrame(EthernetPacket eth) {
        if (routerMac == null) return;
        MacAddress src = eth.getHeader().getSrcAddr();
        MacAddress dst = eth.getHeader().getDstAddr();
        if (src.equals(routerMac) || dst.equals(routerMac)) {
            bytes.addAndGet(eth.length());
        }
    }

    @Override
    public void onArpPacket(ArpPacket arp, EthernetPacket eth) {}

    @Override
    public String getName() {
        return "Трафик с роутером (байт)";
    }

    @Override
    public String getValueAsString() {
        return String.valueOf(bytes.get());
    }

    @Override
    public void reset() {
        bytes.set(0);
    }
}