package se.anatom.ejbca.admin;

/**
 * Issues a new CRL from the CA.
 *
 * @version $Id: CaCreateCrlCommand.java,v 1.7 2004-02-11 10:42:46 herrvendil Exp $
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
        if (args.length < 1) {
	       throw new IllegalAdminCommandException("Usage: CA createcrl <caname>" +
	       		                                                               "If no caname is given then will CRLs for all neccessary CAs be created.");
	    }	
        
        if (args.length == 1) {
        	try{
        	  createCRL((String) null);
        	} catch (Exception e) {
        		throw new ErrorAdminCommandException(e);
        	}        	
        }	
        
        if(args.length == 2){
          try {            
            String caname = args[1];	    
            // createCRL prints info about crl generation            
            createCRL(getIssuerDN(caname));
          } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
          }
        }  
    }

    // execute
}
