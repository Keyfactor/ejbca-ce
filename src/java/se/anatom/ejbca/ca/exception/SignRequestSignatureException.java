package se.anatom.ejbca.ca.exception;

import se.anatom.ejbca.exception.EjbcaException;


/**
 * Error due to invlid signature on certificate request.
 *
 * @version $Id: SignRequestSignatureException.java,v 1.3 2003-06-26 11:43:23 anatom Exp $
 */
public class SignRequestSignatureException extends EjbcaException {
    /**
     * Constructor used to create exception with an errormessage. Calls the same constructor in
     * baseclass <code>Exception</code>.
     *
     * @param message Human redable error message, can not be NULL.
     */
    public SignRequestSignatureException(String message) {
        super(message);
    }
}
