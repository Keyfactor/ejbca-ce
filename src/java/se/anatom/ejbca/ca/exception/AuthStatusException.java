package se.anatom.ejbca.ca.exception;

import se.anatom.ejbca.exception.EjbcaException;


/**
 * Authentication error due to wrong status of user object. To authenticate a user the user must
 * have status new, failed or inprocess.
 *
 * @version $Id: AuthStatusException.java,v 1.3 2003-06-26 11:43:23 anatom Exp $
 */
public class AuthStatusException extends EjbcaException {
    /**
     * Constructor used to create exception with an errormessage. Calls the same constructor in
     * baseclass <code>Exception</code>.
     *
     * @param message Human redable error message, can not be NULL.
     */
    public AuthStatusException(String message) {
        super(message);
    }
}
