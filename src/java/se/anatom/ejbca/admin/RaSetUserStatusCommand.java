package se.anatom.ejbca.admin;

import se.anatom.ejbca.ra.authorization.AuthorizationDeniedException;


/**
 * Changes status for a user in the database, status is defined in
 * se.anatom.ejbca.ra.UserDataLocal.
 *
 * @version $Id: RaSetUserStatusCommand.java,v 1.6 2003-06-26 11:43:22 anatom Exp $
 *
 * @see se.anatom.ejbca.ra.UserDataLocal
 */
public class RaSetUserStatusCommand extends BaseRaAdminCommand {
    /**
     * Creates a new instance of RaSetUserStatusCommand
     *
     * @param args command line arguments
     */
    public RaSetUserStatusCommand(String[] args) {
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
            if (args.length < 3) {
                System.out.println("Usage: RA setuserstatus <username> <status>");
                System.out.println(
                    "Status: NEW=10; FAILED=11; INITIALIZED=20; INPROCESS=30; GENERATED=40; HISTORICAL=50");

                return;
            }

            String username = args[1];
            int status = Integer.parseInt(args[2]);

            try {
                getAdminSession().setUserStatus(administrator, username, status);
                System.out.println("New status for user " + username + " is " + status);
            } catch (AuthorizationDeniedException e) {
                System.out.println("Error : Not authorized to change userdata.");
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }

    // execute
}
