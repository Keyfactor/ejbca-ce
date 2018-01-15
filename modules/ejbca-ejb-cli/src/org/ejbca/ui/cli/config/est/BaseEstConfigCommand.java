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

package org.ejbca.ui.cli.config.est;

import org.ejbca.config.EstConfiguration;
import org.ejbca.ui.cli.config.ConfigBaseCommand;

/**
 * Shows the current server configuration
 * 
 * @version $Id$
 */
public abstract class BaseEstConfigCommand extends ConfigBaseCommand {
     
    private EstConfiguration estConfiguration = null;

    @Override
    public String[] getCommandPath() {
        return new String[] { super.getCommandPath()[0] , "est" };
    }
    
    protected EstConfiguration getEstConfiguration() {
        if (estConfiguration == null) {
            estConfiguration = (EstConfiguration) getGlobalConfigurationSession().getCachedConfiguration(EstConfiguration.EST_CONFIGURATION_ID);
        }
        return estConfiguration;
    }

}
