package com.example;

import org.pcap4j.core.*;
import org.pcap4j.util.MacAddress;
import org.pcap4j.util.NifSelector;

import java.net.InetAddress;
import java.util.Scanner;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Main {
    private static PcapHandle handle;
    private static PacketHandler packetHandler;
    private static Statistics statistics;
    private static ArpSender arpSender;
    private static CommandProcessor commandProcessor;
    private static ExecutorService captureExecutor;

    public static void main(String[] args) {
        try {
            EnvConfig config = new EnvConfig();
            InetAddress localIp = InetAddress.getByName(config.getInterfaceIp());
            byte[] localMac = config.getInterfaceMacBytes();
            if (localMac == null) {
                System.err.println("MAC адрес не задан в .env");
                return;
            }

            PcapNetworkInterface nif = Pcaps.getDevByAddress(localIp);
            if (nif == null) {
                System.err.println("Интерфейс с IP " + config.getInterfaceIp() + " не найден. Выберите вручную:");
                nif = new NifSelector().selectNetworkInterface();
                if (nif == null) {
                    System.err.println("Интерфейс не выбран. Выход");
                    return;
                }
            }

            handle = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);

            statistics = new Statistics();
            String routerMacStr = config.getRouterMac();
            if (routerMacStr != null) {
                try {
                    MacAddress routerMac = MacAddress.getByName(routerMacStr);
                    statistics.setRouterMac(routerMac);
                } catch (IllegalArgumentException e) {
                    System.err.println("Некорректный MAC роутера в .env, игнор");
                }
            }

            packetHandler = new PacketHandler();
            StatisticsUpdater statsUpdater = new StatisticsUpdater(statistics);
            ArpPrinter arpPrinter = new ArpPrinter();
            packetHandler.addProcessor(statsUpdater);
            packetHandler.addProcessor(arpPrinter);

            arpSender = new ArpSender(handle, localMac, localIp, config);
            commandProcessor = new CommandProcessor(arpSender, arpPrinter, statistics);

            captureExecutor = Executors.newSingleThreadExecutor();
            captureExecutor.submit(() -> {
                try {
                    handle.loop(-1, packetHandler);
                } catch (InterruptedException e) {
                    System.out.println("Захват остановлн");
                } catch (PcapNativeException | NotOpenException e) {
                    e.printStackTrace();
                }
            });

            commandProcessor.printHelp();
            Scanner scanner = new Scanner(System.in);
            try {
                while (true) {
                    System.out.print("> ");
                    String line = scanner.nextLine().trim();
                    if (line.isEmpty()) continue;
                    if ("exit".equalsIgnoreCase(line)) {
                        break;
                    }
                    commandProcessor.process(line);
                }
            } finally {
                scanner.close();
            }

            handle.breakLoop();
            captureExecutor.shutdownNow();
            handle.close();
            System.out.println("Программа завершена");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}