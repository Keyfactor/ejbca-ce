package se.anatom.ejbca.admin;

import se.anatom.ejbca.authorization.AuthorizationDeniedException;
import se.anatom.ejbca.ra.raadmin.UserDoesntFullfillEndEntityProfile;


/**
 * Set the (hashed) password for a user in the database.
 *
 * @version $Id: RaSetPwdCommand.java,v 1.8 2003-09-03 14:32:02 herrvendil Exp $
 */
public class RaSetPwdCommand extends BaseRaAdminCommand {
    /**
     * Creates a new instance of RaSetPwdCommand
     *
     * @param args command line arguments
     */
    public RaSetPwdCommand(String[] args) {
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
                System.out.println("Usage: RA setpwd <username> <password>");

                return;
            }

            String username = args[1];
            String password = args[2];
            System.out.println("Setting password (hashed only) " + password + " for user " +
                username);

            try {
                getAdminSession().setPassword(administrator, username, password);
            } catch (AuthorizationDeniedException e) {
                System.out.println("Error : Not authorized to change userdata.");
            } catch (UserDoesntFullfillEndEntityProfile e) {
                System.out.println("Error : Given userdata doesn't fullfill profile.");
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }

    // execute
}
