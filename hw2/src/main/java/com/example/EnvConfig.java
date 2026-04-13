package com.example;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;

public class EnvConfig {
    private static final String KEY_INTERFACE_IP = "INTERFACE_IP";
    private static final String KEY_INTERFACE_MAC = "INTERFACE_MAC";
    private static final String KEY_GATEWAY_IP = "GATEWAY_IP";
    private static final String KEY_ROUTER_IP = "ROUTER_IP";
    private static final String KEY_ROUTER_MAC = "ROUTER_MAC";
    private static final String KEY_DNS_PROVIDER_IP = "DNS_PROVIDER_IP";
    private static final String KEY_ROOT_DNS_IP = "ROOT_DNS_IP";

    private final Map<String, String> env = new HashMap<>();

    public EnvConfig() throws IOException {
        Path path = Paths.get(".env");
        if (!Files.exists(path)) {
            throw new IOException(".env not found");
        }

        try (Stream<String> lines = Files.lines(path)) {
            lines.forEach(line -> {
                String trimmed = line.trim();
                if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                    return;
                }

                int eq = trimmed.indexOf('=');
                if (eq <= 0) {
                    return;
                }

                String key = trimmed.substring(0, eq).trim();
                String value = trimmed.substring(eq + 1).trim();
                env.put(key, value);
            });
        }

        validate();
    }

    public String getInterfaceIp() {
        return env.get(KEY_INTERFACE_IP);
    }

    public byte[] getInterfaceMacBytes() {
        String mac = env.get(KEY_INTERFACE_MAC);
        if (mac == null || mac.isBlank()) {
            return null;
        }
        return parseMac(mac);
    }

    public String getGatewayIp() {
        String gatewayIp = env.get(KEY_GATEWAY_IP);
        if (gatewayIp != null && !gatewayIp.isBlank()) {
            return gatewayIp;
        }

        String routerIp = env.get(KEY_ROUTER_IP);
        if (routerIp != null && !routerIp.isBlank()) {
            return routerIp;
        }

        return null;
    }

    public String getProviderDnsIp() {
        return env.get(KEY_DNS_PROVIDER_IP);
    }

    public String getRootDnsIp() {
        return env.get(KEY_ROOT_DNS_IP);
    }

    public String getRouterIp() {
        return getGatewayIp();
    }

    public String getRouterMac() {
        return env.get(KEY_ROUTER_MAC);
    }

    private void validate() {
        validateRequiredIpv4(KEY_INTERFACE_IP);
        validateRequiredMac(KEY_INTERFACE_MAC);
        validateRequiredIpv4(KEY_DNS_PROVIDER_IP);
        validateRequiredIpv4(KEY_ROOT_DNS_IP);

        String gatewayIp = getGatewayIp();
        if (gatewayIp == null) {
            throw new IllegalArgumentException(
                    "Missing gateway IP. Define GATEWAY_IP (preferred) or ROUTER_IP in .env"
            );
        }

        validateIpv4Value("GATEWAY_IP/ROUTER_IP", gatewayIp);
    }

    private void validateRequiredIpv4(String key) {
        String value = env.get(key);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Missing required key in .env: " + key);
        }

        validateIpv4Value(key, value);
    }

    private void validateRequiredMac(String key) {
        String value = env.get(key);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Missing required key in .env: " + key);
        }

        parseMac(value);
    }

    private static void validateIpv4Value(String key, String value) {
        try {
            InetAddress parsed = InetAddress.getByName(value);
            if (!(parsed instanceof Inet4Address)) {
                throw new IllegalArgumentException("Value for " + key + " must be IPv4, got: " + value);
            }
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException("Invalid IPv4 value for " + key + ": " + value, e);
        }
    }

    private static byte[] parseMac(String mac) {
        String[] hex = mac.split(":");
        if (hex.length != 6) {
            throw new IllegalArgumentException("Invalid MAC format: " + mac);
        }

        byte[] bytes = new byte[6];
        for (int i = 0; i < hex.length; i++) {
            if (hex[i].length() != 2) {
                throw new IllegalArgumentException("Invalid MAC octet in " + mac + ": " + hex[i]);
            }
            bytes[i] = (byte) Integer.parseInt(hex[i], 16);
        }
        return bytes;
    }
}