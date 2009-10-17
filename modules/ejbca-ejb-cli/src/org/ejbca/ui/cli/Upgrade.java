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

/**
 * Implements call to the upgrade function
 *
 * @version $Id$
 */
public class Upgrade extends BaseCommand {

	public String getMainCommand() { return null; }
	public String getSubCommand() { return "upgrade"; }
	public String getDescription() { return "(Use 'ant upgrade' instead of running this directly)"; }

	public void execute(String[] args) throws ErrorAdminCommandException {
		try {
			boolean ret = false;
			String database = System.getProperty("ejbcaDB");
			getLogger().debug("ejbcaDB="+database);
			String upgradeFromVersion = System.getProperty("ejbcaUpgradeFromVersion");
			getLogger().debug("ejbcaUpgradeFromVersion="+upgradeFromVersion);
			if (database == null || upgradeFromVersion == null) {
				getLogger().error("Insufficient information to perform upgrade.");
				return;
			}
			// Check pre-requisites
			if (appServerRunning()) {
				// Upgrade the database
				try {
					args = new String[2];	// Ignore arguments and use system properties instead
					args[0] = database;
					args[1] = upgradeFromVersion;
					ret = getUpgradeSession().upgrade(getAdmin(), args);
				} catch (Exception e) {
					getLogger().error("Can't upgrade: ", e);
					ret = false;
				}
				if (!ret) {
					getLogger().error("Upgrade not performed, see server log for details.");
				} else {
					getLogger().info("Upgrade completed.");   
				}
			} else {
				getLogger().error("The application server must be running.");
				ret = false;
			}
		} catch (Exception e) {
			getLogger().error("Error doing upgrade: ", e);
			System.exit(-1);
		}
	}
}
