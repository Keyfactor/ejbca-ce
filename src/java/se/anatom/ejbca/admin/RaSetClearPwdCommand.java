package se.anatom.ejbca.admin;

import se.anatom.ejbca.authorization.AuthorizationDeniedException;
import se.anatom.ejbca.ra.raadmin.UserDoesntFullfillEndEntityProfile;


/**
 * Set the clear text password for a user in the database.  Clear text passwords are used for batch
 * generation of keystores (pkcs12/pem).
 *
 * @version $Id: RaSetClearPwdCommand.java,v 1.7 2003-09-03 14:32:02 herrvendil Exp $
 */
public class RaSetClearPwdCommand extends BaseRaAdminCommand {
    /**
     * Creates a new instance of RaSetClearPwdCommand
     *
     * @param args command line arguments
     */
    public RaSetClearPwdCommand(String[] args) {
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
                System.out.println("Usage: RA setclearpwd <username> <password>");

                return;
            }

            String username = args[1];
            String password = args[2];
            System.out.println("Setting clear text password " + password + " for user " + username);

            try {
                getAdminSession().setClearTextPassword(administrator, username, password);
            } catch (AuthorizationDeniedException e) {
                System.out.println("Error : Not authorized to change userdata.");
            } catch (UserDoesntFullfillEndEntityProfile e) {
                System.out.println("Error : Given userdata doesn't fullfill end entity profile. : " +
                    e.getMessage());
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }

    // execute
}
