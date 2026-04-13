package com.example;

import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.util.NifSelector;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.Scanner;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Main {

    public static void main(String[] args) {
        EnvConfig config;
        try {
            config = new EnvConfig();
        } catch (IOException | IllegalArgumentException e) {
            System.err.println("Configuration error: " + e.getMessage());
            return;
        }

        PcapHandle handle = null;
        ExecutorService captureExecutor = null;
        try {
            Inet4Address localIp = (Inet4Address) InetAddress.getByName(config.getInterfaceIp());
            PcapNetworkInterface nif = selectNetworkInterface(localIp);
            if (nif == null) {
                return;
            }

            handle = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);

            DnsCaptureService dnsCaptureService = new DnsCaptureService();
            DnsRawClient dnsRawClient = new DnsRawClient(
                    handle,
                    localIp,
                    config.getInterfaceMacBytes(),
                    config
            );
            DnsRawQueryService dnsRawQueryService = new DnsRawQueryService(dnsRawClient);
            DnsMxLookupService dnsMxLookupService = new DnsMxLookupService(config, dnsRawClient);
            DnsComparisonService dnsComparisonService = new DnsComparisonService(config, dnsRawClient);
            CommandProcessor commandProcessor = new CommandProcessor(
                    dnsCaptureService,
                    dnsMxLookupService,
                    dnsComparisonService,
                    dnsRawQueryService
            );
            PacketHandler packetHandler = new PacketHandler();
            packetHandler.addProcessor(dnsCaptureService);
            packetHandler.addProcessor(dnsRawClient);

            captureExecutor = Executors.newSingleThreadExecutor();
            PcapHandle captureHandle = handle;
            captureExecutor.submit(() -> {
                try {
                    captureHandle.loop(-1, packetHandler);
                } catch (InterruptedException e) {
                    System.out.println("Packet capture loop interrupted.");
                    Thread.currentThread().interrupt();
                } catch (Exception e) {
                    System.err.println("Capture loop error: " + e.getMessage());
                }
            });

            commandProcessor.printHelp();
            runConsoleLoop(commandProcessor);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (handle != null && handle.isOpen()) {
                try {
                    handle.breakLoop();
                } catch (NotOpenException ignored) {
                }
            }
            if (captureExecutor != null) {
                captureExecutor.shutdownNow();
            }
            if (handle != null && handle.isOpen()) {
                handle.close();
            }
            System.out.println("Application stopped.");
        }
    }

    private static PcapNetworkInterface selectNetworkInterface(InetAddress localIp)
            throws PcapNativeException, IOException {
        PcapNetworkInterface nif = Pcaps.getDevByAddress(localIp);
        if (nif != null) {
            return nif;
        }

        System.out.println("No interface found by INTERFACE_IP. Please choose manually:");
        return new NifSelector().selectNetworkInterface();
    }

    private static void runConsoleLoop(CommandProcessor commandProcessor) {
        try (Scanner scanner = new Scanner(System.in)) {
            while (true) {
                System.out.print("> ");
                String line = scanner.nextLine().trim();
                if (line.isEmpty()) {
                    continue;
                }

                if ("exit".equalsIgnoreCase(line)) {
                    break;
                }

                commandProcessor.process(line);
            }
        }
    }
}
