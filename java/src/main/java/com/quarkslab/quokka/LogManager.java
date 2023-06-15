package com.quarkslab.quokka;

import ghidra.app.util.importer.MessageLog;


public class LogManager {
    private static LogManager instance;

    private MessageLog log;

    private LogManager(MessageLog log) {
        this.log = log;
    }

    public static LogManager with(MessageLog log) {
        LogManager.instance = new LogManager(log);
        return LogManager.instance;
    }

    public static LogManager getInstance() {
        if (LogManager.instance == null)
            throw new RuntimeException("LogManager has not been previously instanciated");
        return LogManager.instance;
    }

    public void appendMsg(String msg) {
        this.log.appendMsg(msg);
    }

    public static void log(String msg) {
        if (LogManager.instance == null)
            throw new RuntimeException("LogManager has not been previously instanciated");
        LogManager.instance.appendMsg(msg);
    }
}
