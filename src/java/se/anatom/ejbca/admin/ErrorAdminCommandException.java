package se.anatom.ejbca.admin;

/**
 * Exception throws when an error occurs in an Admin Command (IadminCommand)
 *
 * @version $Id: ErrorAdminCommandException.java,v 1.2 2003-06-26 11:43:22 anatom Exp $
 */
public class ErrorAdminCommandException extends se.anatom.ejbca.exception.EjbcaException {
    /**
     * Creates a new instance of ErrorAdminCommandException
     *
     * @param message error message
     */
    public ErrorAdminCommandException(String message) {
        super(message);
    }

    /**
     * Creates a new instance of ErrorAdminCommandException
     *
     * @param exception root cause of error
     */
    public ErrorAdminCommandException(Exception exception) {
        super(exception);
    }
}
