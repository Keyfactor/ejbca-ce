
package se.anatom.ejbca.admin;

/** Exception throws when an error occurs in an Admin Command (IadminCommand)
 *
 * @version $Id: ErrorAdminCommandException.java,v 1.1 2002-04-07 09:55:29 anatom Exp $
 */
public class ErrorAdminCommandException extends se.anatom.ejbca.exception.EjbcaException {

    /** Creates a new instance of ErrorAdminCommandException */
    public ErrorAdminCommandException(String message) {
        super(message);
    }
    /** Creates a new instance of ErrorAdminCommandException */
    public ErrorAdminCommandException(Exception exception) {
        super(exception);
    }

}
