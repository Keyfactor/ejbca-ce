package se.anatom.ejbca.admin;

/**
 * Issues a new CRL from the CA.
 *
 * @version $Id: CaCreateCrlCommand.java,v 1.5 2003-09-03 14:32:02 herrvendil Exp $
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
            if (args.length < 2) {
	       throw new IllegalAdminCommandException("Usage: CA createcrl <caname>");
	    }	
            String caname = args[1];	    
            // createCRL prints info about crl generation            
            createCRL(getIssuerDN(caname));
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }

    // execute
}
