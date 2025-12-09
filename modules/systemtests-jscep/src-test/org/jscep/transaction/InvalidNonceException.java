package org.jscep.transaction;

import net.jcip.annotations.Immutable;

/**
 * This represents the situation where the {@code Nonce}
 * received in a server response does not match the {@code Nonce} sent in the
 * client request, or where the {@code Nonce} received has been used before.
 * 
 * @see Nonce
 */
@Immutable
public class InvalidNonceException extends TransactionException {
    private static final String MISMATCH = "Nonce mismatch.  Sent: %s. Receieved: %s";
    private static final String REPLAY = "Nonce encountered before: %s";
    private static final long serialVersionUID = 3875364340108674893L;

    /**
     * Constructs a new {@code InvalidNonceException<} for a {@code Nonce}
     * mismatch.
     * 
     * @param sent
     *            the sent {@code Nonce}
     * @param recd
     *            the received {@code Nonce}
     */
    public InvalidNonceException(final Nonce sent, final Nonce recd) {
        super(String.format(MISMATCH, sent, recd));
    }

    /**
     * Constructs a new {@code InvalidNonceException<} for a replayed
     * {@code Nonce}
     * 
     * @param nonce
     *            the replayed {@code Nonce}.
     */
    public InvalidNonceException(final Nonce nonce) {
        super(String.format(REPLAY, nonce));
    }
}
