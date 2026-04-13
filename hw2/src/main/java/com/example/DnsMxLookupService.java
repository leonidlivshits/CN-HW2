package com.example;

import org.pcap4j.packet.DnsDomainName;
import org.pcap4j.packet.DnsPacket;
import org.pcap4j.packet.DnsRDataA;
import org.pcap4j.packet.DnsRDataAaaa;
import org.pcap4j.packet.DnsRDataMx;
import org.pcap4j.packet.DnsResourceRecord;
import org.pcap4j.packet.namednumber.DnsResourceRecordType;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public class DnsMxLookupService {
    private static final int DNS_TIMEOUT_MS = 5000;

    private final EnvConfig config;
    private final DnsRawClient rawClient;

    public DnsMxLookupService(EnvConfig config, DnsRawClient rawClient) {
        this.config = config;
        this.rawClient = rawClient;
    }

    public void lookupMx(String domain) {
        if (domain == null || domain.isBlank()) {
            System.out.println("Domain must not be empty.");
            return;
        }

        String normalizedDomain = normalizeDomain(domain);
        try {
            DnsPacket mxResponse = rawClient.query(
                    config.getProviderDnsIp(),
                    normalizedDomain,
                    DnsResourceRecordType.MX,
                    DNS_TIMEOUT_MS
            );

            List<MxRecord> mxRecords = extractMxRecords(mxResponse);
            if (mxRecords.isEmpty()) {
                return;
            }

            for (MxRecord mxRecord : mxRecords) {
                Set<String> ips = resolveIpsForMailHost(mxRecord.exchangeHost());
                if (ips.isEmpty()) {
                    continue;
                }

                System.out.println(mxRecord.exchangeHost());
                for (String ip : ips) {
                    System.out.println(normalizedDomain + " -> " + ip);
                }
            }
        } catch (Exception e) {
            System.err.println("MX lookup failed: " + e.getMessage());
        }
    }

    private List<MxRecord> extractMxRecords(DnsPacket response) {
        List<MxRecord> records = new ArrayList<>();
        byte[] headerRawData = response.getHeader().getRawData();

        for (DnsResourceRecord rr : response.getHeader().getAnswers()) {
            if (!rr.getDataType().equals(DnsResourceRecordType.MX) || !(rr.getRData() instanceof DnsRDataMx mxData)) {
                continue;
            }

            String host = decodeDomain(mxData.getExchange(), headerRawData).toLowerCase(Locale.ROOT);
            int preference = mxData.getPreference() & 0xFFFF;
            records.add(new MxRecord(host, preference));
        }

        Map<String, MxRecord> dedupedByHost = new LinkedHashMap<>();
        for (MxRecord record : records.stream().sorted(Comparator.comparingInt(MxRecord::preference)).toList()) {
            MxRecord existing = dedupedByHost.get(record.exchangeHost());
            if (existing == null || record.preference() < existing.preference()) {
                dedupedByHost.put(record.exchangeHost(), record);
            }
        }

        return new ArrayList<>(dedupedByHost.values());
    }

    private Set<String> resolveIpsForMailHost(String mailHost) {
        Set<String> ips = new LinkedHashSet<>();
        resolveByType(mailHost, DnsResourceRecordType.A, ips);
        resolveByType(mailHost, DnsResourceRecordType.AAAA, ips);
        return ips;
    }

    private void resolveByType(String host, DnsResourceRecordType queryType, Set<String> output) {
        try {
            DnsPacket response = rawClient.query(
                    config.getProviderDnsIp(),
                    host,
                    queryType,
                    DNS_TIMEOUT_MS
            );
            collectIpAnswers(response, queryType, output);
        } catch (Exception ignored) {
        }
    }

    private void collectIpAnswers(DnsPacket response, DnsResourceRecordType expectedType, Set<String> output) {
        for (DnsResourceRecord rr : response.getHeader().getAnswers()) {
            if (!rr.getDataType().equals(expectedType) || rr.getRData() == null) {
                continue;
            }

            if (rr.getRData() instanceof DnsRDataA aData) {
                output.add(aData.getAddress().getHostAddress());
            } else if (rr.getRData() instanceof DnsRDataAaaa aaaaData) {
                output.add(aaaaData.getAddress().getHostAddress());
            }
        }
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

    private record MxRecord(String exchangeHost, int preference) {
    }
}
