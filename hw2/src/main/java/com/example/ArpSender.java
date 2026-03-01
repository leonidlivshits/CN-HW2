package com.example;

import org.pcap4j.core.PcapHandle;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.ArpHardwareType;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.MacAddress;

import java.net.InetAddress;

public class ArpSender {
    private final PcapHandle handle;
    private final byte[] localMac;
    private final InetAddress localIp;
    private final EnvConfig config;

    public ArpSender(PcapHandle handle, byte[] localMac, InetAddress localIp, EnvConfig config) {
        this.handle = handle;
        this.localMac = localMac;
        this.localIp = localIp;
        this.config = config;
    }

    public MacAddress resolveRouterMac() throws Exception {
        InetAddress routerIp = InetAddress.getByName(config.getRouterIp());
        return sendArpRequest(routerIp);
    }

    public MacAddress sendArpRequest(InetAddress targetIp) throws Exception {
        ArpPacket.Builder arpBuilder = new ArpPacket.Builder();
        arpBuilder
                .hardwareType(ArpHardwareType.ETHERNET)
                .protocolType(EtherType.IPV4)
                .hardwareAddrLength((byte) MacAddress.SIZE_IN_BYTES)
                .protocolAddrLength((byte) 4)
                .operation(ArpOperation.REQUEST)
                .srcHardwareAddr(MacAddress.getByAddress(localMac))
                .srcProtocolAddr(localIp)
                .dstHardwareAddr(MacAddress.ETHER_BROADCAST_ADDRESS)
                .dstProtocolAddr(targetIp);

        EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder();
        etherBuilder
                .dstAddr(MacAddress.ETHER_BROADCAST_ADDRESS)
                .srcAddr(MacAddress.getByAddress(localMac))
                .type(EtherType.ARP)
                .payloadBuilder(arpBuilder)
                .paddingAtBuild(true);

        Packet packet = etherBuilder.build();
        System.out.println("Отправка ARP запроса для " + targetIp + "...");
        handle.sendPacket(packet);
        System.out.println("Запрос отправлен. Посмотреть вывод пакетов (команда start) или Wireshark");
        return null;
    }
}