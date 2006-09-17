/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
 
package org.ejbca.core.protocol.ws.client;

//import org.ejbca.core.model.authorization.wsclient.AuthorizationDeniedException;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.ui.cli.IAdminCommand;
import org.ejbca.ui.cli.IllegalAdminCommandException;

/**
 * Revokes a given tokens certificate
 *
 * @version $Id: RevokeTokenCommand.java,v 1.1 2006-09-17 23:00:25 herrvendil Exp $
 */
public class RevokeTokenCommand extends EJBCAWSRABaseCommand implements IAdminCommand{

	
	private static final int ARG_HARDTOKENSN              = 1;
	private static final int ARG_REASON                   = 2;
	
	
    /**
     * Creates a new instance of RevokeTokenCommand
     *
     * @param args command line arguments
     */
    public RevokeTokenCommand(String[] args) {
        super(args);
    }

    /**
     * Runs the command
     *
     * @throws IllegalAdminCommandException Error in command args
     * @throws ErrorAdminCommandException Error running command
     */
    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
      /*  try {   
           
            if(args.length != 3){
            	usage();
            	System.exit(-1);
            }
            
            String hardtokensn = args[ARG_HARDTOKENSN];            
            int reason = getRevokeReason(args[ARG_REASON]);
            
            if(reason == RevokedCertInfo.NOT_REVOKED){
        		getPrintStream().println("Error : Unsupported reason " + reason);
        		usage();
        		System.exit(-1);
            }
                        
            try{

            	getEjbcaRAWS().revokeToken(hardtokensn,reason);            	         
                getPrintStream().println("Token revoked sucessfully");
            }catch(AuthorizationDeniedException e){
            	getPrintStream().println("Error : " + e.getMessage());            
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        } */
    }




	protected void usage() {
		getPrintStream().println("Command used to revoke a tokens certificate");
		getPrintStream().println("Usage : revokecert <hardtokensn> <reason>  \n\n");
		getPrintStream().println("Reason should be one of : ");
		for(int i=1; i< REASON_TEXTS.length-1;i++){
			getPrintStream().print(REASON_TEXTS[i] + ", ");
		}
		getPrintStream().print(REASON_TEXTS[REASON_TEXTS.length-1]);
   }


}
