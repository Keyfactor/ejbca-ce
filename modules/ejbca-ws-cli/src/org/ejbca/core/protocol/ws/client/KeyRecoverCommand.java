package org.ejbca.core.protocol.ws.client;


import org.ejbca.core.protocol.ws.client.gen.ApprovalException_Exception;
import org.ejbca.core.protocol.ws.client.gen.AuthorizationDeniedException_Exception;
import org.ejbca.core.protocol.ws.client.gen.CADoesntExistsException_Exception;
import org.ejbca.core.protocol.ws.client.gen.NotFoundException_Exception;
import org.ejbca.core.protocol.ws.client.gen.WaitingForApprovalException_Exception;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.ui.cli.IAdminCommand;
import org.ejbca.ui.cli.IllegalAdminCommandException;

/**
* 
* THIS COMMAND DOES WORK FROM EXTERNAL RA, HOWEVER, IT IS CURRENTLY NOT POSSIBLE TO SET A NEW
* PASSWORD AND FINALIZE THE ENROLLMENT THORUGH AN EXTERNAL RA USING EJBCA-WS SINCE MOST WS OPERATIONS
* ARE ONLY SUPPORTED LOCALLY (AGAINST THE CA).
* 
* TODO Could be useful to support keyRecoverNewest
*  
* Set status to key recovery for an end entity's certificate.
*
* @version $Id$
*/
public class KeyRecoverCommand extends EJBCAWSRABaseCommand implements IAdminCommand {

    
    private static final int ARG_USERNAME                 = 1;
    private static final int ARG_CERTSNINHEX              = 2;
    private static final int ARG_ISSUERDN                 = 3;
    
    /**
     * Creates a new instance of KeyRecoverCommand
     *
     * @param args command line arguments
     */
    public KeyRecoverCommand(String[] args) {
        super(args);
    }

    /**
     * Runs the command
     *
     * @throws IllegalAdminCommandException Error in command args
     * @throws ErrorAdminCommandException Error running command
     */
    @Override
    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
       try {
           if(args.length != 4){
               getPrintStream().println("Unexpected number of parameters");
               usage();
               System.exit(-1); // NOPMD, it's not a JEE app
           }
           
           String username = args[ARG_USERNAME];
           String certSn = args[ARG_CERTSNINHEX];
           String issuerDn = args[ARG_ISSUERDN];
           
           try {
               getEjbcaRAWS().keyRecover(username, certSn, issuerDn);
               getPrintStream().println("Key recovery sucessfull");
           } catch (AuthorizationDeniedException_Exception e) {
               getPrintStream().println("Authentication failed :\n" + e.getMessage());
           } catch (WaitingForApprovalException_Exception e) {
               getPrintStream().println(e.getMessage());
           } catch (ApprovalException_Exception e) {
               getPrintStream().println(e.getMessage());
           } catch (CADoesntExistsException_Exception e) {
               getPrintStream().println(e.getMessage());
           } catch (NotFoundException_Exception e) {
               getPrintStream().println(e.getMessage());
           }
           
       } catch (Exception e) {
           throw new ErrorAdminCommandException(e);
       }
        
    }

    @Override
    protected void usage() {
        getPrintStream().println("Command used for key recovery");
        getPrintStream().println("Usage : keyrecover <username> <certSerialNr> <issuerDN>");       
    }
    
}
