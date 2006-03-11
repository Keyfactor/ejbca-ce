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
 
package org.ejbca.ui.cli;

import java.rmi.UnmarshalException;

import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.catoken.HardCATokenInfo;
import org.ejbca.core.model.ca.catoken.IHardCAToken;





/**
 * Activates the specified HSM CA.
 *
 * @version $Id: CaActivateCACommand.java,v 1.3 2006-03-11 17:58:34 anatom Exp $
 */
public class CaActivateCACommand extends BaseCaAdminCommand {
    /**
     * Creates a new instance of RaListUsersCommand
     *
     * @param args command line arguments
     */
    public CaActivateCACommand(String[] args) {
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
            if (args.length < 3) {
                getOutputStream().println("Usage: CA acivateca <CA name> <authorization code>");
                return;
            }

            String caname = args[1];
            String authorizationcode = args[2];
                        
            // Get the CAs info and id
            CAInfo cainfo = getCAAdminSessionRemote().getCAInfo(administrator, caname);
            if(cainfo == null){
            	getOutputStream().println("Error: CA " + caname + " cannot be found");	
            	return;            	
            }
                                    
            // Check that ca is and hardtoken ca
            
            if(!(cainfo.getCATokenInfo() instanceof HardCATokenInfo)){
            	getOutputStream().println("Error: CA have a Soft CAToken and cannot be activated");	
            	return;
            }
            
            // Check that CA has correct status.
            if(cainfo.getStatus() == SecConst.CA_OFFLINE || 
            		(cainfo.getStatus() == SecConst.CA_ACTIVE && ((HardCATokenInfo)cainfo.getCATokenInfo()).getCATokenStatus() == IHardCAToken.STATUS_OFFLINE)) {
            	try {
                	getCAAdminSessionRemote().activateCAToken(administrator, cainfo.getCAId(), authorizationcode);            		
            	} catch (UnmarshalException e) {
            		// If we gat a classnotfound we are probably getting an error back from the token, 
            		// with a class we don't have here at the CLI. It is probably invalid PIN
            		getOutputStream().println("Error returned, did you enter the correct PIN?");
            		getOutputStream().println(e.getMessage());
            	}
            }else{
            	getOutputStream().println("Error: CA or CAToken must be offline to be activated.");
            }
            
 
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    } // execute
}
