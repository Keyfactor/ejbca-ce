
package se.anatom.ejbca.admin;

import java.io.*;

import se.anatom.ejbca.ra.UserAdminData;

/** Find details of a user in the database.
 *
 * @version $Id: RaFindUserCommand.java,v 1.1 2002-04-14 08:49:31 anatom Exp $
 */
public class RaFindUserCommand extends BaseRaAdminCommand {

    /** Creates a new instance of RaFindUserCommand */
    public RaFindUserCommand(String[] args) {
        super(args);
    }

    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
        try {
            if (args.length < 2) {
                System.out.println("Usage: RA finduser <username>");
                return;
            }
            String username = args[1];
            UserAdminData data = getAdminSession().findUser(username);
            if (data != null) {
                System.out.println("Found user:");
                System.out.println("username="+data.getUsername());
                System.out.println("dn=\""+data.getDN()+"\"");
                System.out.println("email="+data.getEmail());
                System.out.println("status="+data.getStatus());
                System.out.println("type="+data.getType());
                System.out.println("password="+data.getPassword());
            } else {
                System.out.println("User '"+username+"' does not exist.");
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    } // execute
    
}
