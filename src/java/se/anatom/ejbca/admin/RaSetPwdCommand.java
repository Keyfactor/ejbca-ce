
package se.anatom.ejbca.admin;

import java.io.*;

/** Set the (hashed) password for a user in the database.
 *
 * @version $Id: RaSetPwdCommand.java,v 1.2 2002-04-14 09:11:10 anatom Exp $
 */
public class RaSetPwdCommand extends BaseRaAdminCommand {

    /** Creates a new instance of RaSetPwdCommand */
    public RaSetPwdCommand(String[] args) {
        super(args);
    }

    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
        try {
            if (args.length < 3) {
                System.out.println("Usage: RA setpwd <username> <password>");
                return;
            }
            String username = args[1];
            String password = args[2];
            System.out.println("Setting password (hashed only) "+password+" for user "+username);
            getAdminSession().setPassword(username, password);
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    } // execute
    
}
