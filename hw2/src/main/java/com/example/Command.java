package com.example;

import java.util.function.Consumer;

public class Command {
    private final String name;
    private final String description;
    private final Consumer<String[]> executor;

    public Command(String name, String description, Consumer<String[]> executor) {
        this.name = name;
        this.description = description;
        this.executor = executor;
    }

    public String getName() {
        return name;
    }

    public String getDescription() {
        return description;
    }

    public void execute(String[] args) {
        executor.accept(args);
    }
}