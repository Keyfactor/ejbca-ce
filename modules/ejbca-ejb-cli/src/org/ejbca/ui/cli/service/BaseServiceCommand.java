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

package org.ejbca.ui.cli.service;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.core.ejb.services.ServiceSessionRemote;
import org.ejbca.ui.cli.BaseCommand;
import org.ejbca.ui.cli.CliUsernameException;
import org.ejbca.ui.cli.ErrorAdminCommandException;

/**
 * Base for service commands, contains common functions for service operations
 *
 * @version $Id$
 */
public abstract class BaseServiceCommand extends BaseCommand {

    @Override
    public String getMainCommand() {
        return "service";
    }
    
    @Override
    public void execute(String[] args) throws ErrorAdminCommandException {
        CryptoProviderTools.installBCProvider();
        try {
            args = parseUsernameAndPasswordFromArgs(args);
        } catch (CliUsernameException e) {
            return;
        }
        
        int serviceId = 0;
        if (acceptsServiceName()) {
            final ServiceSessionRemote serviceSession = ejb.getRemoteSession(ServiceSessionRemote.class);
            if (args.length >= 2) {
                serviceId = serviceSession.getServiceId(args[1]);
                if (serviceId == 0 && failIfServiceMissing()) {
                    getLogger().info("Unknown Service: " + args[1]);
                    return;
                }
            }
        }
        
        execute(args, serviceId);
    }
    
    public abstract void execute(String[] args, int serviceId) throws ErrorAdminCommandException;
    
    protected boolean acceptsServiceName() { return true; }
    protected boolean failIfServiceMissing() { return true; }
    
    /** @return the EJB CLI admin */
    protected AuthenticationToken getAdmin() {
        return getAdmin(cliUserName, cliPassword);
    }
}
