package com.example;

import org.pcap4j.packet.DnsPacket;
import org.pcap4j.packet.DnsResourceRecord;
import org.pcap4j.packet.namednumber.DnsResourceRecordType;

import java.util.List;
import java.util.Locale;

public class DnsRawQueryService {
    private static final int DEFAULT_TIMEOUT_MS = 5000;

    private final DnsRawClient rawClient;

    public DnsRawQueryService(DnsRawClient rawClient) {
        this.rawClient = rawClient;
    }

    public void queryAndPrint(String serverIp, String domain, String typeText) {
        try {
            DnsResourceRecordType type = parseType(typeText);
            DnsPacket response = rawClient.query(serverIp, domain, type, DEFAULT_TIMEOUT_MS);
            printResponseSummary(serverIp, domain, type, response);
        } catch (Exception e) {
            System.err.println("Raw DNS query failed: " + e.getMessage());
        }
    }

    private DnsResourceRecordType parseType(String typeText) {
        if (typeText == null || typeText.isBlank()) {
            return DnsResourceRecordType.A;
        }

        String normalized = typeText.trim().toUpperCase(Locale.ROOT);
        return switch (normalized) {
            case "A" -> DnsResourceRecordType.A;
            case "AAAA" -> DnsResourceRecordType.AAAA;
            case "MX" -> DnsResourceRecordType.MX;
            case "NS" -> DnsResourceRecordType.NS;
            case "CNAME" -> DnsResourceRecordType.CNAME;
            case "TXT" -> DnsResourceRecordType.TXT;
            case "PTR" -> DnsResourceRecordType.PTR;
            default -> throw new IllegalArgumentException(
                    "Unsupported RR type: " + typeText + ". Supported: A, AAAA, MX, NS, CNAME, TXT, PTR"
            );
        };
    }

    private void printResponseSummary(
            String serverIp,
            String domain,
            DnsResourceRecordType type,
            DnsPacket response
    ) {
        DnsPacket.DnsHeader header = response.getHeader();
        byte[] headerRawData = header.getRawData();

        System.out.printf(
                "Raw DNS response received: server=%s, domain=%s, type=%s%n",
                serverIp,
                domain,
                type
        );
        System.out.printf(
                "ID=0x%04X, RCODE=%s, QD=%d, AN=%d, NS=%d, AR=%d%n",
                header.getId() & 0xFFFF,
                header.getrCode(),
                header.getQdCountAsInt(),
                header.getAnCountAsInt(),
                header.getNsCountAsInt(),
                header.getArCountAsInt()
        );

        printSection("Answer", header.getAnswers(), headerRawData);
        printSection("Authority", header.getAuthorities(), headerRawData);
        printSection("Additional", header.getAdditionalInfo(), headerRawData);
        System.out.println();
    }

    private void printSection(String sectionName, List<DnsResourceRecord> records, byte[] headerRawData) {
        for (int i = 0; i < records.size(); i++) {
            DnsResourceRecord rr = records.get(i);
            String rData = rr.getRData() == null ? "<empty>" : flatten(rr.getRData().toString("", headerRawData));
            System.out.printf(
                    "%s[%d]: name=%s, type=%s, ttl=%d, rdata=%s%n",
                    sectionName,
                    i,
                    rr.getName().toString(headerRawData),
                    rr.getDataType(),
                    rr.getTtlAsLong(),
                    rData
            );
        }
    }

    private String flatten(String text) {
        return text
                .replace("\r", " ")
                .replace("\n", " ")
                .replaceAll("\\s+", " ")
                .trim();
    }
}
