package com.example;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

public class CommandProcessor {
    private final List<Command> commands = new ArrayList<>();
    private final ArpSender arpSender;
    private final ArpPrinter arpPrinter;
    private final Statistics statistics;

    public CommandProcessor(ArpSender arpSender, ArpPrinter arpPrinter, Statistics statistics) {
        this.arpSender = arpSender;
        this.arpPrinter = arpPrinter;
        this.statistics = statistics;

        commands.add(new Command("help", "показать справку", args -> printHelp()));
        commands.add(new Command("start", "включить вывод всех ARP пакетов", args -> {
            arpPrinter.setEnabled(true);
            System.out.println("Режим вывода arp пакетов включён");
        }));
        commands.add(new Command("stop", "выключить вывод arp пакетов", args -> {
            arpPrinter.setEnabled(false);
            System.out.println("Режим вывода ARP-пакетов выключен.");
        }));
        commands.add(new Command("routermac", "отправить ARP запрос для определения mac роутера", args -> {
            try {
                arpSender.resolveRouterMac();
            } catch (Exception e) {
                System.err.println("Ошибка при отправке ARP запроса: " + e.getMessage());
            }
        }));
        commands.add(new Command("stats", "<секунды> - собрать статистику за указанное время", args -> {
            if (args.length < 2) {
                System.out.println("Укажите время в секундах: stats <секунды>");
            } else {
                try {
                    int seconds = Integer.parseInt(args[1]);
                    collectStats(seconds);
                } catch (NumberFormatException e) {
                    System.out.println("Неверный формат числа.");
                }
            }
        }));
        commands.add(new Command("exit", "завершить программу", args -> {}));
    }

    public void printHelp() {
        System.out.println("Доступные команды:");
        for (Command cmd : commands) {
            String displayName = cmd.getName();
            if (cmd.getName().equals("stats")) {
                displayName = "stats <секунды>";
            }
            System.out.printf("  %-24s - %s%n", displayName, cmd.getDescription());
        }
    }

    public void process(String line) {
        String[] parts = line.split("\\s+");
        String cmdName = parts[0].toLowerCase();

        for (Command cmd : commands) {
            if (cmd.getName().equals(cmdName)) {
                cmd.execute(parts);
                return;
            }
        }
        System.out.println("Неизвестная команда. Введите help.");
    }

    private void collectStats(int seconds) {
        System.out.println("Сбор статистики в течение " + seconds + " секунд...");
        statistics.startCollection();

        try {
            TimeUnit.SECONDS.sleep(seconds);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        statistics.stopCollection();
        statistics.print();
    }
}