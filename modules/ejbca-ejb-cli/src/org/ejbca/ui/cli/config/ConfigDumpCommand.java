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

import org.ejbca.core.ejb.config.GlobalConfigurationSessionRemote;
import org.ejbca.ui.cli.BaseCommand;
import org.ejbca.ui.cli.CliUsernameException;
import org.ejbca.ui.cli.ErrorAdminCommandException;

/**
 * Shows the current server configuration
 * 
 * @version $Id$
 */
public class ConfigDumpCommand extends BaseCommand {

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
        try {
            args = parseUsernameAndPasswordFromArgs(args);
        } catch (CliUsernameException e) {
            return;
        }
        getLogger().info("Trying to fetch currently used server properties...");
        try {
            Properties properties = ejb.getRemoteSession(GlobalConfigurationSessionRemote.class).getAllProperties(getAdmin(cliUserName, cliPassword));
            Enumeration<Object> enumeration = properties.keys();
            while (enumeration.hasMoreElements()) {
                String key = (String) enumeration.nextElement();
                getLogger().info(" " + key + " = " + properties.getProperty(key));
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }        
    }
}
