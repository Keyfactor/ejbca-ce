package se.anatom.ejbca.protocol.exception;

import se.anatom.ejbca.exception.EjbcaException;


/**
 * Error due to some part of the request is not supported.
 *
 * @version $Id: NotSupportedException.java,v 1.1 2004-01-05 18:28:38 anatom Exp $
 */
public class NotSupportedException extends EjbcaException {
    /**
     * Constructor used to create exception with an errormessage. Calls the same constructor in
     * baseclass <code>Exception</code>.
     *
     * @param message Human redable error message, can not be NULL.
     */
    public NotSupportedException(String message) {
        super(message);
    }
    /**
     * Constructor used to create exception with an embedded exception. Calls the same constructor
     * in baseclass <code>Exception</code>.
     *
     * @param exception exception to be embedded.
     */
    public NotSupportedException(Exception exception) {
        super(exception);
    }
}
