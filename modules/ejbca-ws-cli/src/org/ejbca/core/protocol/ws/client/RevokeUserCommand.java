/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
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


import java.util.List;

import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.ejbca.core.protocol.ws.client.gen.AlreadyRevokedException_Exception;
import org.ejbca.core.protocol.ws.client.gen.ApprovalException_Exception;
import org.ejbca.core.protocol.ws.client.gen.AuthorizationDeniedException_Exception;
import org.ejbca.core.protocol.ws.client.gen.UserDataVOWS;
import org.ejbca.core.protocol.ws.client.gen.UserMatch;
import org.ejbca.core.protocol.ws.client.gen.WaitingForApprovalException_Exception;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.ui.cli.IAdminCommand;
import org.ejbca.ui.cli.IllegalAdminCommandException;

/**
 * Revokes a given users certificate and set's it status to REVOKED
 *
 * @version $Id$
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
         try {   
           
            if(args.length != 4){
            	usage();
            	System.exit(-1); // NOPMD, it's not a JEE app
            }
            
            String username = args[ARG_USERNAME];            
            int reason = getRevokeReason(args[ARG_REASON]);
            boolean delete = getDelete(args[ARG_DELETE]);
            
            if(reason == RevokedCertInfo.NOT_REVOKED){
        		getPrintStream().println("Error : Unsupported reason " + reason);
        		usage();
        		System.exit(-1); // NOPMD, it's not a JEE app
            }
                        
            try{
            	UserMatch match = new UserMatch();
            	match.setMatchtype(org.ejbca.util.query.UserMatch.MATCH_TYPE_EQUALS);
            	match.setMatchwith(org.ejbca.util.query.UserMatch.MATCH_WITH_USERNAME);
            	match.setMatchvalue(username);
            	            	
            	List<UserDataVOWS> result = getEjbcaRAWS().findUser(match);
            	if(result == null || result.size() != 1){
            		getPrintStream().println("Error : User doesn't exist.");
            		System.exit(-1); // NOPMD, it's not a JEE app
            	}
            	
            	UserDataVOWS user = result.iterator().next();
            	if(user.getStatus() == EndEntityConstants.STATUS_REVOKED){
              		getPrintStream().println("Error : User already revoked.");
            		System.exit(-1); // NOPMD, it's not a JEE app         		
            	}
            	
            	getEjbcaRAWS().revokeUser(username,reason,delete);            	         
                getPrintStream().println("User revoked sucessfully");
            } catch(AuthorizationDeniedException_Exception e) {
            	getPrintStream().println("Error : " + e.getMessage());            
			} catch (AlreadyRevokedException_Exception e) {
            	getPrintStream().println("This user has already been revoked.");            
			} catch (WaitingForApprovalException_Exception e) {
            	getPrintStream().println("The revocation request has been sent for approval.");            
			} catch (ApprovalException_Exception e) {
            	getPrintStream().println("This revocation has already been requested.");            
			}
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }


	private boolean getDelete(String delete) {
		if(delete.equalsIgnoreCase("true")){
			return true;
		}
		if(delete.equalsIgnoreCase("false")){
			return false;
		}
		usage();
		System.exit(-1); // NOPMD, it's not a JEE app				
		return false; // Should never happen
	}


	protected void usage() {
		getPrintStream().println("Command used to revoke a users certificate");
		getPrintStream().println("Usage : revokeuser <username> <reason> <delete (true|false)> \n\n");
		getPrintStream().println("Reason should be one of : ");
		for(int i=1; i< REASON_TEXTS.length-1;i++){
			getPrintStream().print(REASON_TEXTS[i] + ", ");
		}
		getPrintStream().print(REASON_TEXTS[REASON_TEXTS.length-1]);
   }


}
