package se.anatom.ejbca.admin;

import se.anatom.ejbca.ra.UserAdminData;

import java.util.Collection;
import java.util.Iterator;


/**
 * List users with specified status in the database.
 *
 * @version $Id: RaListUsersCommand.java,v 1.7 2003-06-26 11:43:22 anatom Exp $
 *
 * @see se.anatom.ejbca.ra.UserDataLocal
 */
public class RaListUsersCommand extends BaseRaAdminCommand {
    /**
     * Creates a new instance of RaListUsersCommand
     *
     * @param args command line arguments
     */
    public RaListUsersCommand(String[] args) {
        super(args);
    }

    /**
     * Runs the command
     *
     * @throws IllegalAdminCommandException Error in command args
     * @throws ErrorAdminCommandException Error running command
     */
    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
        try {
            if (args.length < 2) {
                System.out.println("Usage: RA listusers <status>");
                System.out.println(
                    "Status: NEW=10; FAILED=11; INITIALIZED=20; INPROCESS=30; GENERATED=40; HISTORICAL=50");

                return;
            }

            int status = Integer.parseInt(args[1]);
            Collection coll = getAdminSession().findAllUsersByStatus(administrator, status);
            Iterator iter = coll.iterator();

            while (iter.hasNext()) {
                UserAdminData data = (UserAdminData) iter.next();
                System.out.println("User: " + data.getUsername() + ", \"" + data.getDN() +
                    "\", \"" + data.getSubjectAltName() + "\", " + data.getEmail() + ", " +
                    data.getStatus() + ", " + data.getType() + ", " + data.getTokenType());
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }

    // execute
}
