package org.jscep.transaction;

import net.jcip.annotations.Immutable;

/**
 * Represents any failure occurring in the transaction layer.
 */
@Immutable
public class TransactionException extends Exception {
    private static final long serialVersionUID = 1L;

    /**
     * Creates a new {@code TransactionException} caused by the provided
     * {@code Throwable}.
     * 
     * @param cause
     *            the {@code Throwable} that caused the error.
     */
    public TransactionException(final Throwable cause) {
        super(cause);
    }

    /**
     * Creates a new {@code TransactionException} with the provided error
     * message.
     * 
     * @param message
     *            a description of the error condition.
     */
    public TransactionException(final String message) {
        super(message);
    }
}
