package org.jscep.transaction;

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicLong;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.ArrayUtils;

import static java.nio.charset.StandardCharsets.US_ASCII;

/**
 * This class represents a SCEP <code>transactionID</code> attribute.
 */
public final class TransactionId implements Serializable, Comparable<TransactionId> {
    private static final long serialVersionUID = -5248125945726721520L;
    private static final AtomicLong ID_SOURCE = new AtomicLong();
    private final byte[] id;

    /**
     * Creates a new {@code TransactionId} from the provided byte array.
     * 
     * @param id
     *            the ID to copy.
     */
    public TransactionId(final byte[] id) {
        this.id = ArrayUtils.clone(id);
    }

    private TransactionId(final PublicKey pubKey, final String digestAlgorithm) {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance(digestAlgorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        id = new Hex().encode(digest.digest(pubKey.getEncoded()));
    }

    private TransactionId() {
        try {
            id = Long.toHexString(ID_SOURCE.getAndIncrement()).getBytes(US_ASCII.name());
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Creates a new Transaction ID
     * <p>
     * Each call to this method will return the same transaction ID given the
     * same parameters.
     * 
     * @param pubKey
     *            the key on which to base the transaction ID.
     * @param digestAlgorithm
     *            the algorithm to use to digest the key
     * @return the new {@code TransactionID}
     */
    public static TransactionId createTransactionId(final PublicKey pubKey,
            final String digestAlgorithm) {
        return new TransactionId(pubKey, digestAlgorithm);
    }

    /**
     * Creates a new Transaction Id
     * <p>
     * Each call to this method will return a different transaction ID.
     * 
     * @return the new {@code TransactionID}
     */
    public static TransactionId createTransactionId() {
        return new TransactionId();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String toString() {
        try {
            return new String(id, US_ASCII.name());
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
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

        TransactionId that = (TransactionId) o;

        return Arrays.equals(id, that.id);

    }
    
    @Override
    public int compareTo(TransactionId that) {
        for (int i = 0, j = 0; i < this.id.length && j < that.id.length; i++, j++) {
            int a = (this.id[i] & 0xff);
            int b = (that.id[j] & 0xff);
            if (a != b) {
                return a - b;
            }
        }
        return this.id.length - that.id.length;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int hashCode() {
        return Arrays.hashCode(id);

    }
}
