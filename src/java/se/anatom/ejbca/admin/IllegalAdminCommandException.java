
package se.anatom.ejbca.admin;

/** Exception throws when illegal parameters are issued for an Admin Command (IadminCommand)
 *
 * @version $Id: IllegalAdminCommandException.java,v 1.1 2002-04-07 09:55:29 anatom Exp $
 */
public class IllegalAdminCommandException extends se.anatom.ejbca.exception.EjbcaException {

    /** Creates a new instance of IllegalAdminCommandException */
    public IllegalAdminCommandException(String message) {
        super(message);
    }

}
