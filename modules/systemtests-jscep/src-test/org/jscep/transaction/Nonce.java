package org.jscep.transaction;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.ArrayUtils;

/**
 * This class represents the <code>senderNonce</code> and
 * <code>recipientNonce</code> types.
 */
public final class Nonce {
    private static final int NONCE_LENGTH = 16;
    private static final Random RND = new SecureRandom();
    private final byte[] nonce;

    /**
     * Creates a new {@code Nonce} with the given byte array.
     *
     * @param nonce
     *            the byte array.
     */
    public Nonce(final byte[] nonce) {
        this.nonce = ArrayUtils.clone(nonce);
    }

    /**
     * Returns the {@code Nonce} byte array.
     *
     * @return the byte array.
     */
    public byte[] getBytes() {
        return ArrayUtils.clone(nonce);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String toString() {
        return "Nonce [" + new String(Hex.encodeHex(nonce)) + "]";
    }

    /**
     * Generates a new random {@code Nonce}.
     * 
     * This method uses a static {@link SecureRandom} instance as the source of
     * randomness, and can therefore make no guarantee of true uniqueness.
     *
     * @return the generated {@code Nonce}.
     */
    public static Nonce nextNonce() {
        byte[] bytes = new byte[NONCE_LENGTH];
        RND.nextBytes(bytes);

        return new Nonce(bytes);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        Nonce nonce1 = (Nonce) o;

        return Arrays.equals(nonce, nonce1.nonce);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int hashCode() {
        return Arrays.hashCode(nonce);
    }
}
