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
package org.ejbca.ui.cli.config;

import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.ui.cli.infrastructure.command.EjbcaCliUserCommandBase;

/**
 * Basic class for the "config" subcommands.
 * 
 * @version $Id$
 *
 */
public abstract class ConfigBaseCommand extends EjbcaCliUserCommandBase {

    private GlobalConfigurationSessionRemote globalConfigSession = null;

    @Override
    public String[] getCommandPath() {
        return new String[] { "config" };
    }
    

    /** @return the remote EJB reference to GlobalConfigurationSession */
    protected GlobalConfigurationSessionRemote getGlobalConfigurationSession() {
        if (globalConfigSession==null) {
            globalConfigSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
        }
        return globalConfigSession;
    }
}
