package com.example;

import java.util.ArrayList;
import java.util.List;

public class CommandProcessor {
    private final List<Command> commands = new ArrayList<>();
    private final DnsCaptureService dnsCaptureService;
    private final DnsMxLookupService dnsMxLookupService;
    private final DnsComparisonService dnsComparisonService;
    private final DnsRawQueryService dnsRawQueryService;

    public CommandProcessor(
            DnsCaptureService dnsCaptureService,
            DnsMxLookupService dnsMxLookupService,
            DnsComparisonService dnsComparisonService,
            DnsRawQueryService dnsRawQueryService
    ) {
        this.dnsCaptureService = dnsCaptureService;
        this.dnsMxLookupService = dnsMxLookupService;
        this.dnsComparisonService = dnsComparisonService;
        this.dnsRawQueryService = dnsRawQueryService;

        commands.add(new Command("help", "show supported commands", args -> printHelp()));
        commands.add(new Command("dns-capture-start", "start DNS capture mode", args -> dnsCaptureService.startCapture()));
        commands.add(new Command("dns-capture-stop", "stop DNS capture mode", args -> dnsCaptureService.stopCapture()));
        commands.add(new Command("mx", "<domain> - resolve MX endpoint(s) in two-step mode", args -> {
            if (args.length < 2) {
                System.out.println("Usage: mx <domain>");
                return;
            }
            dnsMxLookupService.lookupMx(args[1]);
        }));
        commands.add(new Command(
                "compare-root-provider",
                "query github.com, hse.ru, draw.io via root DNS and provider DNS",
                args -> dnsComparisonService.compareRootAndProviderForDefaultDomains()
        ));
        commands.add(new Command(
                "dns-raw-query",
                "<dns-server-ip> <domain> [rr-type] - send a raw DNS query via pcap",
                args -> {
                    if (args.length < 3) {
                        System.out.println("Usage: dns-raw-query <dns-server-ip> <domain> [rr-type]");
                        return;
                    }
                    String rrType = args.length >= 4 ? args[3] : "A";
                    dnsRawQueryService.queryAndPrint(args[1], args[2], rrType);
                }
        ));
        commands.add(new Command("exit", "exit application", args -> {
        }));
    }

    public void printHelp() {
        System.out.println("Доступные команды:");
        for (Command cmd : commands) {
            System.out.printf("  %-24s - %s%n", cmd.getName(), cmd.getDescription());
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

        System.out.println("Unknown command. Type help.");
    }
}
