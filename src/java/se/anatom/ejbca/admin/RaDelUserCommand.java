
package se.anatom.ejbca.admin;

import java.io.*;

/** Deletes a user from the database.
 *
 * @version $Id: RaDelUserCommand.java,v 1.1 2002-04-14 08:49:31 anatom Exp $
 */
public class RaDelUserCommand extends BaseRaAdminCommand {

    /** Creates a new instance of RaDelUserCommand */
    public RaDelUserCommand(String[] args) {
        super(args);
    }
    
    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
        try {
            if (args.length < 2) {
                System.out.println("Usage: RA deluser <username>");
                return;
            }
            String username = args[1];
            System.out.print("Have you revoked the user [y/N]? ");
            int inp = System.in.read();
            if ( (inp == 121) || (inp==89) ) {
                getAdminSession().deleteUser(username);
                System.out.println("Deleted user "+username);
            } else {
                System.out.println("Delete aborted!");
                System.out.println("Please run 'ra revokeuser "+username+"'.");
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    } // execute
    
}
