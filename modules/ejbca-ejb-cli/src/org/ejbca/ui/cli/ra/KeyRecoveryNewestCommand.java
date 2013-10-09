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

import org.cesecore.certificates.endentity.EndEntityInformation;
import org.ejbca.config.Configuration;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.config.GlobalConfigurationSessionRemote;
import org.ejbca.core.ejb.keyrecovery.KeyRecoverySessionRemote;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.ui.cli.CliUsernameException;
import org.ejbca.ui.cli.ErrorAdminCommandException;

/**
 * Set status to key recovery for an end entity's newest certificate
 *
 * @version $Id$
 */
public class KeyRecoveryNewestCommand extends BaseRaCommand {

    @Override
	public String getSubCommand() { return "keyrecovernewest"; }
    
    @Override
    public String getDescription() { return "Set status to key recovery for an end entity's newest certificate"; }
    
    @Override
    public String[] getSubCommandAliases() {
        return new String[]{};
    }
    
	@Override
    public void execute(String[] args) throws ErrorAdminCommandException {
        try {
            args = parseUsernameAndPasswordFromArgs(args);
        } catch (CliUsernameException e) {
            return;
        }
        try {
    		if (args.length != 2) {
    			getLogger().info("Description: " + getDescription());
    			getLogger().info("Usage: " + getCommand() + " <username>");
    			return;
    		}
    		String username = args[1];
    		boolean usekeyrecovery = ((GlobalConfiguration) ejb.getRemoteSession(GlobalConfigurationSessionRemote.class).getCachedConfiguration(Configuration.GlobalConfigID)).getEnableKeyRecovery();  
    		if(!usekeyrecovery){
    			getLogger().error("Keyrecovery have to be enabled in the system configuration in order to use this command.");
    			return;                   
    		}   
    		if(ejb.getRemoteSession(KeyRecoverySessionRemote.class).isUserMarked(username)){
    			getLogger().error("End entity is already marked for recovery.");
    			return;                     
    		}
    		EndEntityInformation userdata = ejb.getRemoteSession(EndEntityAccessSessionRemote.class).findUser(getAuthenticationToken(cliUserName, cliPassword), username);
    		if(userdata == null){
    			getLogger().error("The user doesn't exist.");
    			return;
    		}
    		if (ejb.getRemoteSession(EndEntityManagementSessionRemote.class).prepareForKeyRecovery(getAuthenticationToken(cliUserName, cliPassword), userdata.getUsername(), userdata.getEndEntityProfileId(), null)) {
        		getLogger().info("Key corresponding to users newest certificate has been marked for recovery.");             
    		} else {
        		getLogger().info("Failed to mark key corresponding to users newest certificate for recovery.");             
    		}
    	} catch (Exception e) {
    		throw new ErrorAdminCommandException(e);
    	}
    }
}
