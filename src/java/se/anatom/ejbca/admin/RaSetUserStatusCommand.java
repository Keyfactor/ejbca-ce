
package se.anatom.ejbca.admin;

import java.io.*;

/** Changes status for a user in the database, status is defined in se.anatom.ejbca.ra.UserData.
 *
 * @see se.anatom.ejbca.ra.UserData
 * @version $Id: RaSetUserStatusCommand.java,v 1.1 2002-04-14 08:49:31 anatom Exp $
 */
public class RaSetUserStatusCommand extends BaseRaAdminCommand {

    /** Creates a new instance of RaSetUserStatusCommand */
    public RaSetUserStatusCommand(String[] args) {
        super(args);
    }

    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
        try {
            if (args.length < 3) {
                System.out.println("Usage: RA setuserstatus <username> <status>");
                System.out.println("Status: NEW=10; FAILED=11; INITIALIZED=20; INPROCESS=30; GENERATED=40; HISTORICAL=50");
                return;
            }
            String username = args[1];
            int status = Integer.parseInt(args[2]);
            System.out.println("New status for user "+username+" is "+status);
            getAdminSession().setUserStatus(username, status);
         } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    } // execute
    
}
