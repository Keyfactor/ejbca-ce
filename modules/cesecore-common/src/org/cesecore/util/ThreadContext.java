package org.cesecore.util;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

public class ThreadContext {

    public static final String REQUEST_ID = "requestId";
    private static final Map<Long, Map<String, String>> contextMap = new HashMap<>();
    private static final SecureRandom secureRandom;

    static {
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.putLong(System.currentTimeMillis());
        secureRandom = new SecureRandom(buffer.array());
    }

    private static Map<String, String> getContextMap() {
        long threadId = Thread.currentThread().getId();
        if (contextMap.get(threadId) == null) {
            contextMap.put(threadId, new HashMap<>());
        }
        return contextMap.get(threadId);
    }

    public static boolean containsRequestId() {
        return getContextMap().get(REQUEST_ID) != null;
    }

    public static void removeRequestId() {
        getContextMap().remove(REQUEST_ID);
    }

    public static String getRequestId() {
        if (containsRequestId()) {
            return getContextMap().get(REQUEST_ID);
        }
        else {
            return null;
        }
    }

    public static void setRequestId(String requestId) {
        getContextMap().put(REQUEST_ID, requestId);
    }

    public static void createRequestIdIfAbsent(String sessionId) {
        if (!containsRequestId()) {
            String id;
            if (sessionId == null) {
                id = String.format("request-id-%06d", secureRandom.nextInt(100_000));
            }
            else {
                id = String.format("session-id-%s", sessionId);
            }
            getContextMap().put(REQUEST_ID, id);
        }
    }

    public static void createRequestIdIfAbsent() {
        createRequestIdIfAbsent(null);
    }

}
