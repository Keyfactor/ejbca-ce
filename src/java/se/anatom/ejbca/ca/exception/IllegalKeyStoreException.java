package se.anatom.ejbca.ca.exception;

import se.anatom.ejbca.exception.EjbcaException;


/**
 * Error due to malformed key store. The cause of failure can be related to illegal key length etc.
 *
 * @version $Id: IllegalKeyStoreException.java,v 1.2 2003-09-09 12:53:49 anatom Exp $
 */
public class IllegalKeyStoreException extends EjbcaException {
    /**
     * Constructor used to create exception with an errormessage. Calls the same constructor in
     * baseclass <code>Exception</code>.
     *
     * @param message Human redable error message, can not be NULL.
     */
    public IllegalKeyStoreException(String message) {
        super(message);
    }
    /**
     * Constructor used to create exception with an embedded exception. Calls the same constructor
     * in baseclass <code>Exception</code>.
     *
     * @param exception exception to be embedded.
     */
    public IllegalKeyStoreException(Exception exception) {
        super(exception);
    }
}
