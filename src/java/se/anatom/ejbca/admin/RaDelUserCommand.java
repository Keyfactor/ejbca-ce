package se.anatom.ejbca.admin;

import se.anatom.ejbca.authorization.AuthorizationDeniedException;


/**
 * Deletes a user from the database.
 *
 * @version $Id: RaDelUserCommand.java,v 1.7 2003-09-03 14:32:02 herrvendil Exp $
 */
public class RaDelUserCommand extends BaseRaAdminCommand {
    /**
     * Creates a new instance of RaDelUserCommand
     *
     * @param args command line arguments
     */
    public RaDelUserCommand(String[] args) {
        super(args);
    }

    /**
     * Runs the command
     *
     * @throws IllegalAdminCommandException Error in command args
     * @throws ErrorAdminCommandException Error running command
     */
    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
        if (args.length < 2) {
            throw new IllegalAdminCommandException("Usage: RA deluser <username>");
        }

        try {
            String username = args[1];
            System.out.print("Have you revoked the user [y/N]? ");

            int inp = System.in.read();

            if ((inp == 121) || (inp == 89)) {
                try {
                    getAdminSession().deleteUser(administrator, username);
                    System.out.println("Deleted user " + username);
                } catch (AuthorizationDeniedException e) {
                    System.out.println("Error : Not authorized to remove user.");
                }
            } else {
                System.out.println("Delete aborted!");
                System.out.println("Please run 'ra revokeuser " + username + "'.");
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }

    // execute
}
