package se.anatom.ejbca.admin;

/**
 * Exception throws when illegal parameters are issued for an Admin Command (IadminCommand)
 *
 * @version $Id: IllegalAdminCommandException.java,v 1.2 2003-06-26 11:43:22 anatom Exp $
 */
public class IllegalAdminCommandException extends se.anatom.ejbca.exception.EjbcaException {
    /**
     * Creates a new instance of IllegalAdminCommandException
     *
     * @param message error message
     */
    public IllegalAdminCommandException(String message) {
        super(message);
    }
}
