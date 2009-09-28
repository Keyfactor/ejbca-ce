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

package org.ejbca.ui.cli;

import java.rmi.RemoteException;
import java.util.Enumeration;
import java.util.Properties;

/**
 * Dump current configuration to standard out.
 *
 * @version $Id: $
 */
public class ConfigDumpCommand extends BaseCaAdminCommand {

    /**
     * Creates a new instance of this class
     *
     * @param args command line arguments
     */
    public ConfigDumpCommand(String[] args) {
        super(args);
    }

    /**
     * Tries to fetch the server properties and dumps them to standard out
     */
	public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
        getOutputStream().println("Trying to fetch currently used server properties..");
        getOutputStream().flush();
        try {
			Properties properties = getConfigurationSession().getAllProperties();
			Enumeration enumeration = properties.keys();
			while (enumeration.hasMoreElements()) {
				String key = (String) enumeration.nextElement();
				getOutputStream().println(" " + key + " = " + properties.getProperty(key));
			}
		} catch (RemoteException e) {
            error("Error getting properties: " + e.getMessage());
		}
	}
}
