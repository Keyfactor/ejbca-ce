package se.anatom.ejbca.ca.exception;

import se.anatom.ejbca.exception.EjbcaException;


/**
 * Error due to malformed certificate request. The cause of failure can be related to ASN.1,
 * algorithm or other
 *
 * @version $Id: SignRequestException.java,v 1.3 2003-06-26 11:43:23 anatom Exp $
 */
public class SignRequestException extends EjbcaException {
    /**
     * Constructor used to create exception with an errormessage. Calls the same constructor in
     * baseclass <code>Exception</code>.
     *
     * @param message Human redable error message, can not be NULL.
     */
    public SignRequestException(String message) {
        super(message);
    }
}
