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
 
package org.ejbca.ui.cli.ca;

import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.core.model.SecConst;
import org.ejbca.ui.cli.ErrorAdminCommandException;

/**
 * Makes the specified HSM CA offline.
 *
 * @version $Id$
 */
public class CaDeactivateCACommand extends BaseCaAdminCommand {

	public String getMainCommand() { return MAINCOMMAND; }
	public String getSubCommand() { return "deactivateca"; }
	public String getDescription() { return "Makes the specified HSM CA offline"; }

    public void execute(String[] args) throws ErrorAdminCommandException {
        try {
            if (args.length < 2) {
    			getLogger().info("Description: " + getDescription());
                getLogger().info("Usage: " + getCommand() + " <CA name> ");
                return;
            }
            String caname = args[1];
            CryptoProviderTools.installBCProvider();
            // Get the CAs info and id
            CAInfo cainfo = ejb.getCAAdminSession().getCAInfo(getAdmin(), caname);
            if(cainfo == null){
            	getLogger().error("CA " + caname + " cannot be found");	
            	return;            	
            }
            if(cainfo.getStatus() == SecConst.CA_ACTIVE){
              ejb.getCAAdminSession().deactivateCAToken(getAdmin(), cainfo.getCAId());                        
              getLogger().info("CA token deactivated.");
            }else{
            	getLogger().error("CA or CAToken must be active to be put offline.");
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }
}
