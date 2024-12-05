package org.cesecore.util;

import java.nio.ByteBuffer;
import java.security.SecureRandom;

public class RequestId {

    protected static final String SEPARATOR = "   ";
    private static final SecureRandom secureRandom;

    static {
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.putLong(System.currentTimeMillis());
        secureRandom = new SecureRandom(buffer.array());
    }

    public static String[] split() {
        return Thread.currentThread().getName().split(SEPARATOR);
    }

    public static void setRequestId(final String requestId) {
        Thread.currentThread().setName(split()[0]+SEPARATOR+requestId);
    }

    private final String originalThreadName;

    public RequestId(final String requestId) {
        originalThreadName = Thread.currentThread().getName();
        final String[] array = originalThreadName.split(SEPARATOR);
        if (array.length <= 1) {
            // There is no previous request-id. Generate a new one.
            String id;
            if (requestId == null) {
                id = String.format("request-id-%06d", secureRandom.nextInt(100_000));
            }
            else {
                id = requestId;
            }
            Thread.currentThread().setName(originalThreadName+SEPARATOR+id);
        }
        else {
            // There is already a request-id. Keep using it.
        }
    }

    public RequestId() {
        this(null);
    }

    public void clear() {
        Thread.currentThread().setName(originalThreadName);
    }

}
