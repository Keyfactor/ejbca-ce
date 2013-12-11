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
package org.ejbca.ui.cli.config;

import org.ejbca.core.ejb.config.GlobalConfigurationSessionRemote;
import org.ejbca.ui.cli.BaseCommand;

/**
 * Basic class for the "config" subcommands.
 * 
 * @version $Id$
 *
 */
public abstract class ConfigBaseCommand extends BaseCommand {

    private GlobalConfigurationSessionRemote globalConfigSession = null;

    @Override
    public String getMainCommand() {
        return "config";
    }

    @Override
    public String[] getMainCommandAliases() {
        return new String[] {};
    }
    
    @Override
    public String[] getSubCommandAliases() {
        return new String[]{};
    }

    /** @return the remote EJB reference to GlobalConfigurationSession */
    protected GlobalConfigurationSessionRemote getGlobalConfigurationSession() {
        if (globalConfigSession==null) {
            globalConfigSession = ejb.getRemoteSession(GlobalConfigurationSessionRemote.class);
        }
        return globalConfigSession;
    }
}
