package com.example;

import org.pcap4j.packet.DnsDomainName;
import org.pcap4j.packet.DnsPacket;
import org.pcap4j.packet.DnsRDataA;
import org.pcap4j.packet.DnsRDataAaaa;
import org.pcap4j.packet.DnsRDataCName;
import org.pcap4j.packet.DnsRDataMx;
import org.pcap4j.packet.DnsRDataNs;
import org.pcap4j.packet.DnsResourceRecord;
import org.pcap4j.packet.namednumber.DnsRCode;
import org.pcap4j.packet.namednumber.DnsResourceRecordType;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class DnsComparisonService {
    private static final int DNS_TIMEOUT_MS = 7000;
    private static final List<String> DEFAULT_DOMAINS = List.of("github.com", "hse.ru", "draw.io");

    private final EnvConfig config;
    private final DnsRawClient rawClient;

    public DnsComparisonService(EnvConfig config, DnsRawClient rawClient) {
        this.config = config;
        this.rawClient = rawClient;
    }

    public void compareRootAndProviderForDefaultDomains() {
        System.out.println("Root DNS server: " + config.getRootDnsIp());
        System.out.println("Provider DNS server: " + config.getProviderDnsIp());

        for (String domain : DEFAULT_DOMAINS) {
            compareForDomain(domain);
            System.out.println();
        }
    }

    private void compareForDomain(String domain) {
        String normalizedDomain = normalizeDomain(domain);
        System.out.println("Domain: " + normalizedDomain);

        System.out.println("Root DNS response:");
        queryAndPrint(config.getRootDnsIp(), normalizedDomain, true);

        System.out.println("Provider DNS response:");
        queryAndPrint(config.getProviderDnsIp(), normalizedDomain, false);
    }

    private void queryAndPrint(String dnsServerIp, String domain, boolean rootScenario) {
        try {
            DnsPacket response = rawClient.query(
                    dnsServerIp,
                    domain,
                    DnsResourceRecordType.A,
                    DNS_TIMEOUT_MS
            );
            printDnsSummary(response);
            printSection("Answer", response.getHeader().getAnswers(), response.getHeader().getRawData());
            printSection("Authority", response.getHeader().getAuthorities(), response.getHeader().getRawData());
            printSection("Additional", response.getHeader().getAdditionalInfo(), response.getHeader().getRawData());
            System.out.println("Interpretation: " + interpretResponse(response, rootScenario));
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }
    }

    private void printDnsSummary(DnsPacket response) {
        DnsPacket.DnsHeader h = response.getHeader();
        System.out.printf(
                "ID=0x%04X, RCODE=%s, RA=%s, AA=%s, QD=%d, AN=%d, NS=%d, AR=%d%n",
                h.getId() & 0xFFFF,
                h.getrCode(),
                h.isRecursionAvailable(),
                h.isAuthoritativeAnswer(),
                h.getQdCountAsInt(),
                h.getAnCountAsInt(),
                h.getNsCountAsInt(),
                h.getArCountAsInt()
        );
    }

    private void printSection(String sectionName, List<DnsResourceRecord> records, byte[] headerRawData) {
        if (records.isEmpty()) {
            return;
        }

        List<String> lines = new ArrayList<>();
        for (DnsResourceRecord rr : records) {
            lines.add(formatRecord(rr, headerRawData));
        }

        int limit = Math.min(lines.size(), 12);
        for (int i = 0; i < limit; i++) {
            System.out.println(sectionName + "[" + i + "]: " + lines.get(i));
        }
        if (lines.size() > limit) {
            System.out.println(sectionName + ": ... +" + (lines.size() - limit) + " records");
        }
    }

    private String formatRecord(DnsResourceRecord rr, byte[] headerRawData) {
        String name = decodeDomain(rr.getName(), headerRawData);
        String type = rr.getDataType().name();
        String data = extractRecordData(rr, headerRawData);
        return "name=" + name + ", type=" + type + ", ttl=" + rr.getTtlAsLong() + ", data=" + data;
    }

    private String extractRecordData(DnsResourceRecord rr, byte[] headerRawData) {
        if (rr.getRData() == null) {
            return "<empty>";
        }

        if (rr.getRData() instanceof DnsRDataA aData) {
            return aData.getAddress().getHostAddress();
        }
        if (rr.getRData() instanceof DnsRDataAaaa aaaaData) {
            return aaaaData.getAddress().getHostAddress();
        }
        if (rr.getRData() instanceof DnsRDataNs nsData) {
            return decodeDomain(nsData.getNsDName(), headerRawData);
        }
        if (rr.getRData() instanceof DnsRDataCName cNameData) {
            return decodeDomain(cNameData.getCName(), headerRawData);
        }
        if (rr.getRData() instanceof DnsRDataMx mxData) {
            return "pref=" + (mxData.getPreference() & 0xFFFF) + ", exchange=" + decodeDomain(mxData.getExchange(), headerRawData);
        }

        return rr.getRData().toString("", headerRawData)
                .replace("\r", " ")
                .replace("\n", " ")
                .replaceAll("\\s+", " ")
                .trim();
    }

    private String interpretResponse(DnsPacket response, boolean rootScenario) {
        DnsPacket.DnsHeader h = response.getHeader();
        if (!h.getrCode().equals(DnsRCode.NO_ERROR)) {
            return "DNS server returned error RCODE=" + h.getrCode();
        }

        if (h.getAnCountAsInt() == 0 && h.getNsCountAsInt() > 0) {
            return rootScenario
                    ? "Referral/delegation: root points to next authoritative zone servers."
                    : "Referral response: provider did not return final A answer.";
        }

        if (containsAddressAnswer(response.getHeader().getAnswers())) {
            return rootScenario
                    ? "Final IP answer returned directly by root (uncommon but valid for some cases)."
                    : "Final recursive answer with IP addresses.";
        }

        if (containsType(response.getHeader().getAnswers(), DnsResourceRecordType.CNAME)) {
            return "Alias chain (CNAME) returned; additional resolution may be needed.";
        }

        if (h.getAnCountAsInt() == 0) {
            return "No answer records in response.";
        }

        return "Answer received; inspect records in Answer/Authority/Additional sections.";
    }

    private boolean containsAddressAnswer(List<DnsResourceRecord> records) {
        return containsType(records, DnsResourceRecordType.A)
                || containsType(records, DnsResourceRecordType.AAAA);
    }

    private boolean containsType(List<DnsResourceRecord> records, DnsResourceRecordType type) {
        for (DnsResourceRecord rr : records) {
            if (rr.getDataType().equals(type)) {
                return true;
            }
        }
        return false;
    }

    private String decodeDomain(DnsDomainName domainName, byte[] headerRawData) {
        try {
            if (domainName.getPointer() != null) {
                return domainName.decompress(headerRawData);
            }
            return domainName.getName();
        } catch (Exception ignored) {
            return domainName.getName();
        }
    }

    private String normalizeDomain(String domain) {
        String normalized = domain.trim().toLowerCase(Locale.ROOT);
        if (normalized.endsWith(".")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized;
    }
}
