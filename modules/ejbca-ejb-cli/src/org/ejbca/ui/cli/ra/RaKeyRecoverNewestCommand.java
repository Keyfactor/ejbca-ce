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
 
package org.ejbca.ui.cli.ra;

import javax.ejb.EJB;

import org.ejbca.core.ejb.keyrecovery.KeyRecoverySessionRemote;
import org.ejbca.core.ejb.ra.UserAdminSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.RaAdminSessionRemote;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.ui.cli.ErrorAdminCommandException;

/**
 * Set status to key recovery for a user's newest certificate
 *
 * @version $Id$
 */
public class RaKeyRecoverNewestCommand extends BaseRaAdminCommand {

    @EJB
    private KeyRecoverySessionRemote keyRecoverySession;
    
    @EJB
    private RaAdminSessionRemote raAdminSession;
    
    @EJB
    private UserAdminSessionRemote userAdminSession;
    
	public String getMainCommand() { return MAINCOMMAND; }
	public String getSubCommand() { return "keyrecovernewest"; }
	public String getDescription() { return "Set status to key recovery for a user's newest certificate"; }

    public void execute(String[] args) throws ErrorAdminCommandException {
    	try {
    		if (args.length != 2) {
    			getLogger().info("Description: " + getDescription());
    			getLogger().info("Usage: " + getCommand() + " <username>");
    			return;
    		}
    		String username = args[1];
    		boolean usekeyrecovery = raAdminSession.loadGlobalConfiguration(getAdmin()).getEnableKeyRecovery();  
    		if(!usekeyrecovery){
    			getLogger().error("Keyrecovery have to be enabled in the system configuration in order to use this command.");
    			return;                   
    		}   
    		if(keyRecoverySession.isUserMarked(getAdmin(),username)){
    			getLogger().error("User is already marked for recovery.");
    			return;                     
    		}
    		UserDataVO userdata = userAdminSession.findUser(getAdmin(), username);
    		if(userdata == null){
    			getLogger().error("The user doesn't exist.");
    			return;
    		}
    		if (userAdminSession.prepareForKeyRecovery(getAdmin(), userdata.getUsername(), userdata.getEndEntityProfileId(), null)) {
        		getLogger().info("Key corresponding to users newest certificate has been marked for recovery.");             
    		} else {
        		getLogger().info("Failed to mark key corresponding to users newest certificate for recovery.");             
    		}
    	} catch (Exception e) {
    		throw new ErrorAdminCommandException(e);
    	}
    }
}
