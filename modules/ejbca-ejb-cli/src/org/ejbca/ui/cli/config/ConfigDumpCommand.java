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

import java.util.Enumeration;
import java.util.Properties;

import org.ejbca.core.ejb.upgrade.ConfigurationSessionRemote;
import org.ejbca.ui.cli.BaseCommand;
import org.ejbca.ui.cli.ErrorAdminCommandException;

/**
 * Shows the current server configuration
 * 
 * @version $Id$
 */
public class ConfigDumpCommand extends BaseCommand {

    private ConfigurationSessionRemote configurationSession = ejb.getConfigurationSession();

    public String getMainCommand() {
        return "config";
    }

    public String getSubCommand() {
        return "dump";
    }

    public String getDescription() {
        return "Shows the current server configuration";
    }

    /**
     * Tries to fetch the server properties and dumps them to standard out
     */
    public void execute(String[] args) throws ErrorAdminCommandException {
        getLogger().info("Trying to fetch currently used server properties..");

        Properties properties = configurationSession.getAllProperties();
        Enumeration enumeration = properties.keys();
        while (enumeration.hasMoreElements()) {
            String key = (String) enumeration.nextElement();
            getLogger().info(" " + key + " = " + properties.getProperty(key));
        }

    }
}
