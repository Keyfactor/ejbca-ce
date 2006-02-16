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

import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.catoken.HardCATokenInfo;





/**
 * Makes the specified HSM CA offline.
 *
 * @version $Id: CaDeactivateCACommand.java,v 1.1 2006-02-16 05:51:43 herrvendil Exp $
 */
public class CaDeactivateCACommand extends BaseCaAdminCommand {
    /**
     * Creates a new instance of RaListUsersCommand
     *
     * @param args command line arguments
     */
    public CaDeactivateCACommand(String[] args) {
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
                getOutputStream().println("Usage: CA deactivateca <CA name> ");
                return;
            }

            String caname = args[1];
                        
            // Get the CAs info and id
            CAInfo cainfo = getCAAdminSessionRemote().getCAInfo(administrator, caname);
            if(cainfo == null){
            	getOutputStream().println("Error: CA " + caname + " cannot be found");	
            	return;            	
            }
            
            // Check that ca is and hardtoken ca
            if(!(cainfo.getCATokenInfo() instanceof HardCATokenInfo)){
            	getOutputStream().println("Error: CA have a Soft CAToken and cannot be deactivated");	
            	return;
            }
            
            getCAAdminSessionRemote().deactivateCAToken(administrator, cainfo.getCAId());                        
            
 
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    } // execute
}
