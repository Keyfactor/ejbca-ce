package org.jscep.message;

import net.jcip.annotations.Immutable;

/**
 * This {@code Exception} is thrown whenever jscep is unable to decode a SCEP
 * secure message object.
 */
@Immutable
public class MessageDecodingException extends Exception {
    /**
     * Serialization ID.
     */
    private static final long serialVersionUID = -6111956271602335933L;

    /**
     * Creates a new {@code MessageDecodingException} with the provided cause.
     * 
     * @param cause
     *            the initial cause of the decoding exception.
     */
    public MessageDecodingException(final Throwable cause) {
        super(cause);
    }

    /**
     * Creates a new {@code MessageDecodingException} with the provided error
     * message.
     * 
     * @param message
     *            the description of the decoding exception.
     */
    public MessageDecodingException(final String message) {
        super(message);
    }
}
