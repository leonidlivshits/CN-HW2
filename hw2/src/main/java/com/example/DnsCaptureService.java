package com.example;

import org.pcap4j.packet.DnsPacket;
import org.pcap4j.packet.DnsQuestion;
import org.pcap4j.packet.DnsResourceRecord;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;

import java.util.List;

public class DnsCaptureService implements PacketProcessor {
    private static final int DNS_PORT = 53;
    private volatile boolean captureEnabled = false;

    public void startCapture() {
        if (captureEnabled) {
            System.out.println("DNS capture mode is already enabled.");
            return;
        }

        captureEnabled = true;
        System.out.println("DNS capture mode enabled.");
        System.out.println("Listening for DNS packets (UDP/TCP 53) in promiscuous mode.");
    }

    public void stopCapture() {
        if (!captureEnabled) {
            System.out.println("DNS capture mode is already disabled.");
            return;
        }

        captureEnabled = false;
        System.out.println("DNS capture mode disabled.");
    }

    @Override
    public void processPacket(Packet packet) {
        if (!captureEnabled) {
            return;
        }

        DnsPacket dnsPacket = extractDnsPacket(packet);
        if (dnsPacket == null) {
            return;
        }

        printDnsPacket(packet, dnsPacket);
    }

    private DnsPacket extractDnsPacket(Packet packet) {
        DnsPacket parsedByPcap = packet.get(DnsPacket.class);
        if (parsedByPcap != null) {
            return parsedByPcap;
        }

        UdpPacket udpPacket = packet.get(UdpPacket.class);
        if (udpPacket != null && isDnsPort(udpPacket.getHeader().getSrcPort().valueAsInt(), udpPacket.getHeader().getDstPort().valueAsInt())) {
            Packet payload = udpPacket.getPayload();
            if (payload == null) {
                return null;
            }

            byte[] raw = payload.getRawData();
            try {
                return DnsPacket.newPacket(raw, 0, raw.length);
            } catch (Exception ignored) {
                return null;
            }
        }

        TcpPacket tcpPacket = packet.get(TcpPacket.class);
        if (tcpPacket != null && isDnsPort(tcpPacket.getHeader().getSrcPort().valueAsInt(), tcpPacket.getHeader().getDstPort().valueAsInt())) {
            return parseDnsOverTcp(tcpPacket);
        }

        return null;
    }

    private DnsPacket parseDnsOverTcp(TcpPacket tcpPacket) {
        Packet payload = tcpPacket.getPayload();
        if (payload == null) {
            return null;
        }

        byte[] raw = payload.getRawData();
        if (raw.length < 2) {
            return null;
        }

        int dnsLength = ((raw[0] & 0xFF) << 8) | (raw[1] & 0xFF);
        if (dnsLength <= 0 || raw.length < dnsLength + 2) {
            return null;
        }

        try {
            return DnsPacket.newPacket(raw, 2, dnsLength);
        } catch (Exception ignored) {
            return null;
        }
    }

    private static boolean isDnsPort(int srcPort, int dstPort) {
        return srcPort == DNS_PORT || dstPort == DNS_PORT;
    }

    private void printDnsPacket(Packet packet, DnsPacket dnsPacket) {
        DnsPacket.DnsHeader header = dnsPacket.getHeader();
        byte[] headerRawData = header.getRawData();

        System.out.println("DNS packet");
        System.out.printf(
                "Transport: %s, %s -> %s%n",
                detectTransport(packet),
                endpoint(packet, true),
                endpoint(packet, false)
        );
        System.out.printf(
                "ID=0x%04X, QR=%s, OPCODE=%s, RCODE=%s%n",
                header.getId() & 0xFFFF,
                header.isResponse() ? "response" : "query",
                header.getOpCode(),
                header.getrCode()
        );
        System.out.printf(
                "Flags: AA=%s TC=%s RD=%s RA=%s AD=%s CD=%s%n",
                header.isAuthoritativeAnswer(),
                header.isTruncated(),
                header.isRecursionDesired(),
                header.isRecursionAvailable(),
                header.isAuthenticData(),
                header.isCheckingDisabled()
        );
        System.out.printf(
                "Counts: QD=%d AN=%d NS=%d AR=%d%n",
                header.getQdCountAsInt(),
                header.getAnCountAsInt(),
                header.getNsCountAsInt(),
                header.getArCountAsInt()
        );

        printQuestions(header.getQuestions(), headerRawData);
        printRecords("Answer", header.getAnswers(), headerRawData);
        printRecords("Authority", header.getAuthorities(), headerRawData);
        printRecords("Additional", header.getAdditionalInfo(), headerRawData);
        System.out.println();
    }

    private void printQuestions(List<DnsQuestion> questions, byte[] headerRawData) {
        for (int i = 0; i < questions.size(); i++) {
            DnsQuestion q = questions.get(i);
            System.out.printf(
                    "Question[%d]: qname=%s, qtype=%s, qclass=%s%n",
                    i,
                    q.getQName().toString(headerRawData),
                    q.getQType(),
                    q.getQClass()
            );
        }
    }

    private void printRecords(String section, List<DnsResourceRecord> records, byte[] headerRawData) {
        for (int i = 0; i < records.size(); i++) {
            DnsResourceRecord rr = records.get(i);
            String rdata = rr.getRData() == null ? "<empty>" : flatten(rr.getRData().toString("", headerRawData));
            System.out.printf(
                    "%s[%d]: name=%s, type=%s, class=%s, ttl=%d, rdata=%s%n",
                    section,
                    i,
                    rr.getName().toString(headerRawData),
                    rr.getDataType(),
                    rr.getDataClass(),
                    rr.getTtlAsLong(),
                    rdata
            );
        }
    }

    private String endpoint(Packet packet, boolean source) {
        int port = extractPort(packet, source);

        IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
        if (ipV4Packet != null) {
            String ip = source
                    ? ipV4Packet.getHeader().getSrcAddr().getHostAddress()
                    : ipV4Packet.getHeader().getDstAddr().getHostAddress();
            return port >= 0 ? ip + ":" + port : ip;
        }

        IpV6Packet ipV6Packet = packet.get(IpV6Packet.class);
        if (ipV6Packet != null) {
            String ip = source
                    ? ipV6Packet.getHeader().getSrcAddr().getHostAddress()
                    : ipV6Packet.getHeader().getDstAddr().getHostAddress();
            return port >= 0 ? "[" + ip + "]:" + port : ip;
        }

        EthernetPacket ethernetPacket = packet.get(EthernetPacket.class);
        if (ethernetPacket != null) {
            String mac = source
                    ? ethernetPacket.getHeader().getSrcAddr().toString()
                    : ethernetPacket.getHeader().getDstAddr().toString();
            return port >= 0 ? mac + ":" + port : mac;
        }

        return "unknown";
    }

    private int extractPort(Packet packet, boolean source) {
        UdpPacket udpPacket = packet.get(UdpPacket.class);
        if (udpPacket != null) {
            return source
                    ? udpPacket.getHeader().getSrcPort().valueAsInt()
                    : udpPacket.getHeader().getDstPort().valueAsInt();
        }

        TcpPacket tcpPacket = packet.get(TcpPacket.class);
        if (tcpPacket != null) {
            return source
                    ? tcpPacket.getHeader().getSrcPort().valueAsInt()
                    : tcpPacket.getHeader().getDstPort().valueAsInt();
        }

        return -1;
    }

    private String detectTransport(Packet packet) {
        if (packet.get(UdpPacket.class) != null) {
            return "UDP";
        }
        if (packet.get(TcpPacket.class) != null) {
            return "TCP";
        }
        return "UNKNOWN";
    }

    private String flatten(String text) {
        return text
                .replace("\r", " ")
                .replace("\n", " ")
                .replaceAll("\\s+", " ")
                .trim();
    }
}
