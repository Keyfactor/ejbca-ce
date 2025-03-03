/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.util;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Objects;

public final class RequestId implements AutoCloseable {

    protected static final String SEPARATOR = ": ";
    private static final SecureRandom secureRandom;

    static {
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.putLong(System.currentTimeMillis());
        secureRandom = new SecureRandom(buffer.array());
    }

    public static RequestId parse() {
        String[] array = Thread.currentThread().getName().split(SEPARATOR);
        return array.length >= 2 ? new RequestId(array[0], array[1]) : null;
    }

    private final String originalThreadName;
    private final String id;

    private RequestId(String originalThreadName, String id) {
        this.originalThreadName = originalThreadName;
        this.id = id;
        Thread.currentThread().setName(originalThreadName + SEPARATOR + id);
    }

    public RequestId(String id) {
        this(Thread.currentThread().getName(), id);
    }

    public RequestId() {
        this.originalThreadName = Thread.currentThread().getName();
        RequestId parsed = parse();
        if (parsed == null) {
            this.id = String.format("%08d", secureRandom.nextInt(10_000_000));
            Thread.currentThread().setName(originalThreadName + SEPARATOR + id);
        } else {
            this.id = parsed.id;
        }
    }

    public String getOriginalThreadName() {
        return originalThreadName;
    }

    public String getId() {
        return id;
    }

    @Override
    public void close() {
        Thread.currentThread().setName(originalThreadName);
    }

    @Override
    public boolean equals(Object o) {
        return o != null &&
                o.getClass().equals(this.getClass()) &&
                originalThreadName.equals(((RequestId) o).originalThreadName) &&
                id.equals(((RequestId) o).id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(originalThreadName, id);
    }

    @Override
    public String toString() {
        return String.format("{\n   \"originalThreadName\" : \"%s\",\n   \"id\"                 : \"%s\"\n}", originalThreadName, id);
    }

}
