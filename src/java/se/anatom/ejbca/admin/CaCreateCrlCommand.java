package se.anatom.ejbca.admin;

/**
 * Issues a new CRL from the CA.
 *
 * @version $Id: CaCreateCrlCommand.java,v 1.4 2003-06-26 11:43:22 anatom Exp $
 */
public class CaCreateCrlCommand extends BaseCaAdminCommand {
    /**
     * Creates a new instance of CaCreateCrlCommand
     *
     * @param args command line arguments
     */
    public CaCreateCrlCommand(String[] args) {
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
            // createCRL prints info about crl generation
            createCRL();
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }

    // execute
}
