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
import org.ejbca.core.model.ra.UserDataConstants;
//import org.ejbca.core.protocol.ws.wsclient.UserDataVOWS;
//import org.ejbca.core.protocol.ws.wsclient.UserMatch;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.ui.cli.IAdminCommand;
import org.ejbca.ui.cli.IllegalAdminCommandException;

/**
 * Revokes a given users certificate and set's it status to REVOKED
 *
 * @version $Id: RevokeUserCommand.java,v 1.1 2006-09-17 23:00:25 herrvendil Exp $
 */
public class RevokeUserCommand extends EJBCAWSRABaseCommand implements IAdminCommand{

	
	private static final int ARG_USERNAME                 = 1;
	private static final int ARG_REASON                   = 2;
	private static final int ARG_DELETE                   = 3;
	
	
    /**
     * Creates a new instance of RevokeTokenCommand
     *
     * @param args command line arguments
     */
    public RevokeUserCommand(String[] args) {
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
           
            if(args.length != 4){
            	usage();
            	System.exit(-1);
            }
            
            String username = args[ARG_USERNAME];            
            int reason = getRevokeReason(args[ARG_REASON]);
            boolean delete = getDelete(args[ARG_DELETE]);
            
            if(reason == RevokedCertInfo.NOT_REVOKED){
        		getPrintStream().println("Error : Unsupported reason " + reason);
        		usage();
        		System.exit(-1);
            }
                        
            try{
            	UserDataVOWS[] result = getEjbcaRAWS().findUser(new UserMatch(org.ejbca.util.query.UserMatch.MATCH_TYPE_EQUALS,username,org.ejbca.util.query.UserMatch.MATCH_WITH_USERNAME));
            	if(result == null || result.length != 1){
            		getPrintStream().println("Error : User doesn't exist.");
            		System.exit(-1);
            	}
            	
            	if(result[0].getStatus() == UserDataConstants.STATUS_REVOKED){
              		getPrintStream().println("Error : User already revoked.");
            		System.exit(-1);          		
            	}
            	
            	getEjbcaRAWS().revokeUser(username,reason,delete);            	         
                getPrintStream().println("User revoked sucessfully");
            }catch(AuthorizationDeniedException e){
            	getPrintStream().println("Error : " + e.getMessage());            
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }*/
    }


	private boolean getDelete(String delete) {
		if(delete.equalsIgnoreCase("true")){
			return true;
		}
		if(delete.equalsIgnoreCase("false")){
			return false;
		}
		usage();
		System.exit(-1);				
		return false; // Should never happen
	}


	protected void usage() {
		getPrintStream().println("Command used to revoke a users certificate");
		getPrintStream().println("Usage : revokecert <hardtokensn> <reason> <delete (true|false)> \n\n");
		getPrintStream().println("Reason should be one of : ");
		for(int i=1; i< REASON_TEXTS.length-1;i++){
			getPrintStream().print(REASON_TEXTS[i] + ", ");
		}
		getPrintStream().print(REASON_TEXTS[REASON_TEXTS.length-1]);
   }


}
