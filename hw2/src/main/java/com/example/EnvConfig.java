package com.example;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

public class EnvConfig {
    private final Map<String, String> env = new HashMap<>();

    public EnvConfig() throws IOException {
        Path path = Paths.get(".env");
        if (!Files.exists(path)) {
            throw new IOException(".env не найден");
        }
        Files.lines(path).forEach(line -> {
            line = line.trim();
            if (line.isEmpty() || line.startsWith("#")) return;
            int eq = line.indexOf('=');
            if (eq > 0) {
                String key = line.substring(0, eq).trim();
                String value = line.substring(eq + 1).trim();
                env.put(key, value);
            }
        });
    }

    public String getInterfaceIp() {
        return env.get("INTERFACE_IP");
    }

    public byte[] getInterfaceMacBytes() {
        String mac = env.get("INTERFACE_MAC");
        if (mac == null) return null;
        return parseMac(mac);
    }

    public String getRouterIp() {
        return env.get("ROUTER_IP");
    }

    public String getRouterMac() {
        return env.get("ROUTER_MAC");
    }

    private static byte[] parseMac(String mac) {
        String[] hex = mac.split(":");
        byte[] bytes = new byte[6];
        for (int i = 0; i < 6; i++) {
            bytes[i] = (byte) Integer.parseInt(hex[i], 16);
        }
        return bytes;
    }
}