package se.anatom.ejbca.admin;

/**
 * Issues a new CRL from the CA.
 *
 * @version $Id: CaCreateCrlCommand.java,v 1.6 2003-11-10 09:39:41 anatom Exp $
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
        if (args.length < 2) {
	       throw new IllegalAdminCommandException("Usage: CA createcrl <caname>");
	    }	
        try {            
            String caname = args[1];	    
            // createCRL prints info about crl generation            
            createCRL(getIssuerDN(caname));
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }

    // execute
}
