package org.ejbca.util;

import org.apache.log4j.Logger;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class RequestId implements AutoCloseable {

    private static final Logger log = Logger.getLogger(RequestId.class);

    protected static final String SEPARATOR = "   ";
    private static final SecureRandom secureRandom;
    private static final Map<Long, String> originalNames;
    private static final Map<Long, RequestId> instances;

    static {
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.putLong(System.currentTimeMillis());
        secureRandom = new SecureRandom(buffer.array());
        originalNames = new HashMap<>();
        instances = new HashMap<>();
    }

    public static String getOriginalName() {
        Thread currentThread = Thread.currentThread();
        originalNames.putIfAbsent(currentThread.getId(), currentThread.getName().split(SEPARATOR)[0]);
        return originalNames.get(currentThread.getId());
    }

    public static RequestId getCurrent() {
        return instances.get(Thread.currentThread().getId());
    }

    public static RequestId getCurrentOrCreate() {
        Thread currentThread = Thread.currentThread();
        RequestId instance = instances.get(currentThread.getId());
        if (instance == null) {
            String id = String.format("request-id-%06d", secureRandom.nextInt(100_000));
            instance = new RequestId(id);
            instances.put(currentThread.getId(), instance);
        }
        instance.increaseCounter();
        return instance;
    }

    private final String id;
    private int counter;

    private RequestId(final String id) {
        this.id = id;
        this.counter = 0;
        Thread.currentThread().setName(getOriginalName()+SEPARATOR+id);
        log.info("Start of request");
    }

    private void increaseCounter() {
        counter++;
    }

    public String getId() {
        return id;
    }

    public int getCounter() {
        return counter;
    }

    public void close(boolean recursive) {
        if (counter > 0) {
            counter--;
            if (recursive || counter == 0) {
                log.info("End of request");
                counter = 0;
                Thread currentThread = Thread.currentThread();
                instances.remove(currentThread.getId());
                currentThread.setName(getOriginalName());
            }
        }
    }

    @Override
    public void close() {
        close(false);
    }

    public static void closeAll() {
        Set<Thread> threads = Thread.getAllStackTraces().keySet();
        for (Thread thread : threads) {
            var originalName = thread.getName().split(SEPARATOR)[0];
            thread.setName(originalName);
        }
        instances.clear();
        originalNames.clear();
    }
}
