package com.yukasl.backcode.service;

import org.springframework.stereotype.Service;
import java.util.Queue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;

@Service
public class CommandQueueService {
    // Key: hostId, Value: Queue of commands
    private final ConcurrentHashMap<String, Queue<String>> commandMap = new ConcurrentHashMap<>();

    public void addCommand(String hostId, String command) {
        commandMap.computeIfAbsent(hostId, k -> new ConcurrentLinkedQueue<>()).add(command);
    }

    public String pollCommand(String hostId) {
        Queue<String> queue = commandMap.get(hostId);
        if (queue != null && !queue.isEmpty()) {
            return queue.poll();
        }
        return null;
    }
}
