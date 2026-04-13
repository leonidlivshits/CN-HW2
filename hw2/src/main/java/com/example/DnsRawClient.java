package com.example;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.packet.DnsDomainName;
import org.pcap4j.packet.DnsPacket;
import org.pcap4j.packet.DnsQuestion;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Rfc791Tos;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.namednumber.DnsClass;
import org.pcap4j.packet.namednumber.DnsOpCode;
import org.pcap4j.packet.namednumber.DnsRCode;
import org.pcap4j.packet.namednumber.DnsResourceRecordType;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.packet.namednumber.UdpPort;
import org.pcap4j.util.MacAddress;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Collections;
import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;

public class DnsRawClient implements PacketProcessor {
    private static final int DNS_PORT = 53;
    private static final int MIN_EPHEMERAL_PORT = 49152;
    private static final int MAX_EPHEMERAL_PORT = 65535;
    private static final int MAX_REGISTRATION_ATTEMPTS = 200;

    private final PcapHandle handle;
    private final Inet4Address localIp;
    private final MacAddress localMac;
    private final EnvConfig config;
    private final ConcurrentMap<QueryKey, BlockingQueue<DnsPacket>> pendingResponses = new ConcurrentHashMap<>();

    public DnsRawClient(PcapHandle handle, Inet4Address localIp, byte[] localMacBytes, EnvConfig config) {
        this.handle = Objects.requireNonNull(handle, "handle");
        this.localIp = Objects.requireNonNull(localIp, "localIp");
        this.config = Objects.requireNonNull(config, "config");
        this.localMac = MacAddress.getByAddress(Objects.requireNonNull(localMacBytes, "localMacBytes"));
    }

    public DnsPacket query(
            String dnsServerIp,
            String domain,
            DnsResourceRecordType queryType,
            int timeoutMs
    ) throws UnknownHostException, NotOpenException, InterruptedException, PcapNativeException {
        if (timeoutMs <= 0) {
            throw new IllegalArgumentException("Timeout must be positive.");
        }

        Inet4Address dnsServer = parseIpv4Address(dnsServerIp, "dns server");
        String normalizedDomain = normalizeDomain(domain);
        DnsResourceRecordType normalizedType = Objects.requireNonNull(queryType, "queryType");
        MacAddress destinationMac = resolveNextHopMac();

        PendingQuery pendingQuery = registerPendingQuery(dnsServer.getHostAddress());
        try {
            DnsPacket dnsQueryPacket = buildDnsQueryPacket(
                    pendingQuery.key.transactionId,
                    normalizedDomain,
                    normalizedType
            );
            Packet frame = buildEthernetFrame(
                    destinationMac,
                    dnsServer,
                    pendingQuery.key.sourcePort,
                    dnsQueryPacket
            );

            handle.sendPacket(frame);

            DnsPacket response = pendingQuery.queue.poll(timeoutMs, TimeUnit.MILLISECONDS);
            if (response == null) {
                throw new IllegalStateException(
                        "DNS response timeout (" + timeoutMs + " ms) for "
                                + normalizedDomain + " [" + normalizedType + "] via " + dnsServerIp
                );
            }

            return response;
        } finally {
            pendingResponses.remove(pendingQuery.key);
        }
    }

    @Override
    public void processPacket(Packet packet) {
        UdpPacket udpPacket = packet.get(UdpPacket.class);
        if (udpPacket == null) {
            return;
        }

        int sourcePort = udpPacket.getHeader().getSrcPort().valueAsInt();
        if (sourcePort != DNS_PORT) {
            return;
        }

        DnsPacket dnsPacket = extractDnsFromUdp(udpPacket);
        if (dnsPacket == null || !dnsPacket.getHeader().isResponse()) {
            return;
        }

        IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
        if (ipV4Packet == null) {
            return;
        }

        QueryKey key = new QueryKey(
                ipV4Packet.getHeader().getSrcAddr().getHostAddress(),
                udpPacket.getHeader().getDstPort().valueAsInt(),
                dnsPacket.getHeader().getId() & 0xFFFF
        );
        BlockingQueue<DnsPacket> queue = pendingResponses.get(key);
        if (queue != null) {
            queue.offer(dnsPacket);
        }
    }

    private DnsPacket extractDnsFromUdp(UdpPacket udpPacket) {
        DnsPacket direct = udpPacket.get(DnsPacket.class);
        if (direct != null) {
            return direct;
        }

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

    private PendingQuery registerPendingQuery(String dnsServerIp) {
        ThreadLocalRandom random = ThreadLocalRandom.current();
        for (int i = 0; i < MAX_REGISTRATION_ATTEMPTS; i++) {
            int sourcePort = random.nextInt(MIN_EPHEMERAL_PORT, MAX_EPHEMERAL_PORT + 1);
            int transactionId = random.nextInt(0, 65536);
            QueryKey key = new QueryKey(dnsServerIp, sourcePort, transactionId);
            BlockingQueue<DnsPacket> queue = new ArrayBlockingQueue<>(1);
            if (pendingResponses.putIfAbsent(key, queue) == null) {
                return new PendingQuery(key, queue);
            }
        }

        throw new IllegalStateException("Unable to reserve unique DNS query key for response tracking.");
    }

    private DnsPacket buildDnsQueryPacket(int transactionId, String domain, DnsResourceRecordType queryType) {
        DnsQuestion question = new DnsQuestion.Builder()
                .qName(buildDomainName(domain))
                .qType(queryType)
                .qClass(DnsClass.IN)
                .build();

        return new DnsPacket.Builder()
                .id((short) transactionId)
                .response(false)
                .opCode(DnsOpCode.QUERY)
                .authoritativeAnswer(false)
                .truncated(false)
                .recursionDesired(true)
                .recursionAvailable(false)
                .reserved(false)
                .authenticData(false)
                .checkingDisabled(false)
                .rCode(DnsRCode.NO_ERROR)
                .qdCount((short) 1)
                .anCount((short) 0)
                .nsCount((short) 0)
                .arCount((short) 0)
                .questions(Collections.singletonList(question))
                .answers(Collections.emptyList())
                .authorities(Collections.emptyList())
                .additionalInfo(Collections.emptyList())
                .build();
    }

    private Packet buildEthernetFrame(
            MacAddress destinationMac,
            Inet4Address dnsServer,
            int sourcePort,
            DnsPacket dnsPacket
    ) {
        UdpPacket.Builder udpBuilder = new UdpPacket.Builder()
                .srcPort(UdpPort.getInstance((short) sourcePort))
                .dstPort(UdpPort.DOMAIN)
                .srcAddr(localIp)
                .dstAddr(dnsServer)
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true)
                .payloadBuilder(dnsPacket.getBuilder());

        IpV4Packet.Builder ipBuilder = new IpV4Packet.Builder()
                .version(IpVersion.IPV4)
                .tos(IpV4Rfc791Tos.newInstance((byte) 0))
                .ttl((byte) 64)
                .protocol(IpNumber.UDP)
                .srcAddr(localIp)
                .dstAddr(dnsServer)
                .identification((short) ThreadLocalRandom.current().nextInt(0, 65536))
                .reservedFlag(false)
                .dontFragmentFlag(false)
                .moreFragmentFlag(false)
                .fragmentOffset((short) 0)
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true)
                .paddingAtBuild(true)
                .payloadBuilder(udpBuilder);

        EthernetPacket.Builder ethernetBuilder = new EthernetPacket.Builder()
                .srcAddr(localMac)
                .dstAddr(destinationMac)
                .type(EtherType.IPV4)
                .payloadBuilder(ipBuilder)
                .paddingAtBuild(true);

        return ethernetBuilder.build();
    }

    private MacAddress resolveNextHopMac() {
        String routerMac = config.getRouterMac();
        if (routerMac == null || routerMac.isBlank()) {
            throw new IllegalStateException(
                    "ROUTER_MAC is required in .env for raw DNS packet sending."
            );
        }
        return MacAddress.getByName(routerMac);
    }

    private DnsDomainName buildDomainName(String domain) {
        String[] labels = domain.split("\\.");
        return new DnsDomainName.Builder().labels(labels).build();
    }

    private static Inet4Address parseIpv4Address(String rawIp, String fieldName) throws UnknownHostException {
        if (rawIp == null || rawIp.isBlank()) {
            throw new IllegalArgumentException("Missing " + fieldName + " IP.");
        }

        InetAddress parsed = InetAddress.getByName(rawIp);
        if (!(parsed instanceof Inet4Address)) {
            throw new IllegalArgumentException("Expected IPv4 for " + fieldName + ": " + rawIp);
        }

        return (Inet4Address) parsed;
    }

    private static String normalizeDomain(String domain) {
        if (domain == null) {
            throw new IllegalArgumentException("Domain must not be null.");
        }

        String normalized = domain.trim().toLowerCase(Locale.ROOT);
        if (normalized.endsWith(".")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }

        if (normalized.isEmpty()) {
            throw new IllegalArgumentException("Domain must not be empty.");
        }

        String[] labels = normalized.split("\\.");
        for (String label : labels) {
            if (label.isBlank()) {
                throw new IllegalArgumentException("Domain contains empty label: " + domain);
            }
            if (label.length() > 63) {
                throw new IllegalArgumentException("DNS label is too long: " + label);
            }
        }

        return normalized;
    }

    private static final class PendingQuery {
        private final QueryKey key;
        private final BlockingQueue<DnsPacket> queue;

        private PendingQuery(QueryKey key, BlockingQueue<DnsPacket> queue) {
            this.key = key;
            this.queue = queue;
        }
    }

    private static final class QueryKey {
        private final String dnsServerIp;
        private final int sourcePort;
        private final int transactionId;

        private QueryKey(String dnsServerIp, int sourcePort, int transactionId) {
            this.dnsServerIp = dnsServerIp;
            this.sourcePort = sourcePort;
            this.transactionId = transactionId;
        }

        @Override
        public boolean equals(Object o) {
            if (!(o instanceof QueryKey other)) {
                return false;
            }
            return sourcePort == other.sourcePort
                    && transactionId == other.transactionId
                    && dnsServerIp.equals(other.dnsServerIp);
        }

        @Override
        public int hashCode() {
            int result = dnsServerIp.hashCode();
            result = 31 * result + sourcePort;
            result = 31 * result + transactionId;
            return result;
        }
    }
}
