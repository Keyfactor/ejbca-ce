
package se.anatom.ejbca.admin;

import java.io.*;

/** Set the clear text password for a user in the database. 
 * Clear text passwords are used for batch generation of keystores (pkcs12/pem).
 *
 * @version $Id: RaSetClearPwdCommand.java,v 1.1 2002-04-14 08:49:31 anatom Exp $
 */
public class RaSetClearPwdCommand extends BaseRaAdminCommand {

    /** Creates a new instance of RaSetClearPwdCommand */
    public RaSetClearPwdCommand(String[] args) {
        super(args);
    }

    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
        try {
            if (args.length < 3) {
                System.out.println("Usage: RA setclearpwd <username> <password>");
                return;
            }
            String username = args[1];
            String password = args[2];
            System.out.println("Setting clear text password "+password+" for user "+username);
            getAdminSession().setClearTextPassword(username, password);
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    } // execute
    
}
