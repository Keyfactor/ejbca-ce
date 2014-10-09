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

package org.ejbca.ui.cli.config.scep;

import org.ejbca.config.ScepConfiguration;
import org.ejbca.ui.cli.config.ConfigBaseCommand;

/**
 * Shows the current server configuration
 * 
 * @version $Id: BaseCmpConfigCommand.java 18666 2014-03-24 13:37:16Z mikekushner $
 */
public abstract class BaseScepConfigCommand extends ConfigBaseCommand {
     
    private ScepConfiguration scepConfiguration = null;

    @Override
    public String[] getCommandPath() {
        return new String[] { super.getCommandPath()[0] , "scep" };
    }
    
    protected ScepConfiguration getScepConfiguration() {
        if (scepConfiguration == null) {
            scepConfiguration = (ScepConfiguration) getGlobalConfigurationSession().getCachedConfiguration(ScepConfiguration.SCEP_CONFIGURATION_ID);
        }
        return scepConfiguration;
    }

}
