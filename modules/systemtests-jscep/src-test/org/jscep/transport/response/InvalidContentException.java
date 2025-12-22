package org.jscep.transport.response;

import net.jcip.annotations.Immutable;

/**
 * {@code InvalidContentException} is thrown if a {@link ScepResponseHandler}
 * is unable to parse the content returned by the SCEP server.
 */
@Immutable
public class InvalidContentException extends ContentException {
    private static final long serialVersionUID = 8144078591967730995L;

    /**
     * Creates a new {@code InvalidContentException} with the provided cause.
     * 
     * @param cause
     *            the cause of the error.
     */
    public InvalidContentException(final Throwable cause) {
        super(cause);
    }

    /**
     * Creates a new {@code InvalidContentException} with the provided message.
     * 
     * @param message
     *            a description of the error condition.
     */
    public InvalidContentException(final String message) {
        super(message);
    }
}
