package se.anatom.ejbca.protocol.exception;

import se.anatom.ejbca.exception.EjbcaException;


/**
 * Error due to malformed request. The cause of failure can be related to ASN.1 issues etc.
 *
 * @version $Id: MalformedRequestException.java,v 1.1 2003-10-26 15:13:53 anatom Exp $
 */
public class MalformedRequestException extends EjbcaException {
    /**
     * Constructor used to create exception with an errormessage. Calls the same constructor in
     * baseclass <code>Exception</code>.
     *
     * @param message Human redable error message, can not be NULL.
     */
    public MalformedRequestException(String message) {
        super(message);
    }
    /**
     * Constructor used to create exception with an embedded exception. Calls the same constructor
     * in baseclass <code>Exception</code>.
     *
     * @param exception exception to be embedded.
     */
    public MalformedRequestException(Exception exception) {
        super(exception);
    }
}
