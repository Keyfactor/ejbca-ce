package org.jscep.message;

import net.jcip.annotations.Immutable;

/**
 * This {@code Exception} is thrown whenever jscep is unable to encode a SCEP
 * secure message object.
 */
@Immutable
public class MessageEncodingException extends Exception {
    /**
     * Serialization ID.
     */
    private static final long serialVersionUID = -6111956271602335933L;

    /**
     * Creates a new {@code MessageEncodingException} with the provided cause.
     * 
     * @param cause
     *            the initial cause of the encoding exception.
     */
    public MessageEncodingException(final Throwable cause) {
        super(cause);
    }

    /**
     * Creates a new {@code MessageEncodingException} with the provided error
     * message.
     * 
     * @param message
     *            the description of the encoding exception.
     */
    public MessageEncodingException(final String message) {
        super(message);
    }
}
