package se.anatom.ejbca.admin;

/**
 * Starts an external service needed for user administrations, runs in the same JVM.
 *
 * @version $Id: RaStartServiceCommand.java,v 1.4 2003-06-26 11:43:22 anatom Exp $
 */
public class RaStartServiceCommand extends BaseRaAdminCommand {
    /**
     * Creates a new instance of StartServiceCommand
     *
     * @param args command line arguments
     */
    public RaStartServiceCommand(String[] args) {
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
            getAdminSession().startExternalService(args);
            System.out.println("External service started");
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }

    // execute
}
