package com.example;

import com.example.metrics.*;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.util.MacAddress;

import java.util.ArrayList;
import java.util.List;

public class Statistics {
    private final List<Metric> metrics = new ArrayList<>();
    private boolean collecting = false;
    private final TrafficWithRouterMetric trafficMetric;

    public Statistics() {
        metrics.add(new TotalEthernetFramesMetric());
        metrics.add(new TotalArpPacketsMetric());
        metrics.add(new UniqueMacsMetric());
        metrics.add(new BroadcastEthernetMetric());
        metrics.add(new ArpBroadcastMetric());
        metrics.add(new GratuitousArpMetric());
        metrics.add(new ArpRequestResponsePairsMetric());
        trafficMetric = new TrafficWithRouterMetric();
        metrics.add(trafficMetric);
    }

    public void setRouterMac(MacAddress routerMac) {
        trafficMetric.setRouterMac(routerMac);
    }

    public void startCollection() {
        reset();
        collecting = true;
    }

    public void stopCollection() {
        collecting = false;
    }

    private void reset() {
        for (Metric m : metrics) {
            m.reset();
        }
    }

    public void updateEthernetFrame(EthernetPacket eth) {
        if (!collecting) return;
        for (Metric m : metrics) {
            m.onEthernetFrame(eth);
        }
    }

    public void updateArpPacket(ArpPacket arp, EthernetPacket eth) {
        if (!collecting) return;
        for (Metric m : metrics) {
            m.onArpPacket(arp, eth);
        }
    }

    public void print() {
        System.out.println("СТАТИСТИКА");
        for (Metric m : metrics) {
            System.out.println(m.getName() + ": " + m.getValueAsString());
        }
    }
}