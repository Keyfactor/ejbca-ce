package org.jscep.transaction;

import java.util.Map;
import java.util.WeakHashMap;

/**
 * This class provides support for detecting replay attacks.
 */
public final class NonceQueue {
    private static final int DEFAULT_QUEUE_SIZE = 20;
    private final Map<Nonce, Boolean> backingQueue;

    /**
     * Creates a new {@code NonceQueue}.
     */
    public NonceQueue() {
        this.backingQueue = new WeakHashMap<Nonce, Boolean>(DEFAULT_QUEUE_SIZE);
    }

    /**
     * Inserts the specified {@code Nonce} into this queue.
     * 
     * @param nonce
     *            the nonce to add.
     */
    public synchronized void add(final Nonce nonce) {
        backingQueue.put(nonce, Boolean.FALSE);
    }

    /**
     * Checks the queue for the given {@code Nonce}.
     * 
     * @param nonce
     *            the {@code Nonce} to check for.
     * @return {@code true} if the {@code Nonce} is present, {@code false}
     *         otherwise.
     */
    public synchronized boolean contains(final Nonce nonce) {
        return backingQueue.containsKey(nonce);
    }
}
