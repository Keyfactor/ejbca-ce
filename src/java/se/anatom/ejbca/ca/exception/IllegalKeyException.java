package se.anatom.ejbca.ca.exception;

import se.anatom.ejbca.exception.EjbcaException;


/**
 * Error due to malformed key. The cause of failure can be related to illegal key length etc.
 *
 * @version $Id: IllegalKeyException.java,v 1.2 2003-06-26 11:43:23 anatom Exp $
 */
public class IllegalKeyException extends EjbcaException {
    /**
     * Constructor used to create exception with an errormessage. Calls the same constructor in
     * baseclass <code>Exception</code>.
     *
     * @param message Human redable error message, can not be NULL.
     */
    public IllegalKeyException(String message) {
        super(message);
    }
}
