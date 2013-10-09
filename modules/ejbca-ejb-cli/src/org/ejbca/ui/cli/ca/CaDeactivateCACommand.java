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

import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.ui.cli.CliUsernameException;
import org.ejbca.ui.cli.ErrorAdminCommandException;

/**
 * Makes the specified HSM CA offline.
 *
 * @version $Id$
 */
public class CaDeactivateCACommand extends BaseCaAdminCommand {

    @Override
	public String getSubCommand() { return "deactivateca"; }
    @Override
    public String getDescription() { return "Makes the specified HSM CA offline"; }

    @Override
    public void execute(String[] args) throws ErrorAdminCommandException {
        try {
            args = parseUsernameAndPasswordFromArgs(args);
        } catch (CliUsernameException e) {
            return;
        }
        
        try {
            if (args.length < 2) {
    			getLogger().info("Description: " + getDescription());
                getLogger().info("Usage: " + getCommand() + " <CA name> ");
                return;
            }
            String caname = args[1];
            CryptoProviderTools.installBCProvider();
            // Get the CAs info and id
            CAInfo cainfo = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(getAuthenticationToken(cliUserName, cliPassword), caname);
            if(cainfo == null){
            	getLogger().error("CA " + caname + " cannot be found");	
            	return;            	
            }
            final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = ejb.getRemoteSession(CryptoTokenManagementSessionRemote.class);
            final int cryptoTokenId = cainfo.getCAToken().getCryptoTokenId();
            final boolean tokenOnline = cryptoTokenManagementSession.isCryptoTokenStatusActive(getAuthenticationToken(cliUserName, cliPassword), cryptoTokenId);
            if (cainfo.getStatus() == CAConstants.CA_ACTIVE || tokenOnline) {
                if (cainfo.getStatus() == CAConstants.CA_ACTIVE) {
                    ejb.getRemoteSession(CAAdminSessionRemote.class).deactivateCAService(getAuthenticationToken(cliUserName, cliPassword), cainfo.getCAId());
                    getLogger().info("CA Service deactivated.");
                }
                if (tokenOnline) {
                    cryptoTokenManagementSession.deactivate(getAuthenticationToken(cliUserName, cliPassword), cryptoTokenId);
                    getLogger().info("CA CryptoToken deactivated.");
                }
            } else {
            	getLogger().error("CA Service or CryptoToken must be active for this command to do anything.");
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }
}
