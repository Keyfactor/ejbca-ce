package org.jscep.transport;

import net.jcip.annotations.Immutable;

/**
 * This {@code Exception} is thrown for any error that occurs in the transport
 * layer.
 */
@Immutable
public class TransportException extends Exception {
    private static final long serialVersionUID = 7384278241045962726L;

    /**
     * Constructs a new {@code TransportException} for the provided message and
     * cause.
     * 
     * @param message
     *            a description of the error condition.
     * @param cause
     *            the cause of the error.
     */
    public TransportException(final String message, final Throwable cause) {
        super(message, cause);
    }

    /**
     * Constructs a new {@code TransportException} for the provided cause.
     * 
     * @param cause
     *            the cause of the error.
     */
    public TransportException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new {@code TransportException} for the provided message.
     * 
     * @param message
     *            a description of the error condition.
     */
    public TransportException(final String message) {
        super(message);
    }
}
