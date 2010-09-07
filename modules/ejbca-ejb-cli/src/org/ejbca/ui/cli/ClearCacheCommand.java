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

import java.util.List;

import org.ejbca.util.CliTools;


/**
 * Clears caches used internally by EJBCA. The caches are used to limit the number of database queries issued to the database.
 * See conf/cache.properties.sample for configuration of caches.
 *
 * @author Tomas Gustavsson, PrimeKey Solutions AB
 * @version $Id$
 */
public class ClearCacheCommand extends BaseCommand {

	public String getMainCommand() { return null; }
	public String getSubCommand() { return "clearcache"; }
	public String getDescription() { return "Clears caches used internally by EJBCA."; }

	public void execute(final String[] args) throws ErrorAdminCommandException {
        if (args.length < 2) {
        	getLogger().info("Description: " + getDescription());
        	getLogger().info("See conf/cache.properties.sample for config options. This command should only be needed if cache times are set yo very high values.");
            getLogger().info("Usage: " + getCommand() + " -all -globalconf -eeprofile -certprofile -authorization -logconf -ca");
            getLogger().info("Where arguments are optional, but you have to provide at least one");
        	return;
        }		

		// Get and remove switches
		final List<String> argsList = CliTools.getAsModifyableList(args);
		final boolean all = argsList.remove("-all");
		final boolean globalconf = argsList.remove("-globalconf") || all;
		final boolean eeprofile = argsList.remove("-eeprofile") || all;
		final boolean certprofile = argsList.remove("-certprofile") || all;
		final boolean authorization = argsList.remove("-authorization") || all;
		final boolean logconf = argsList.remove("-logconf") || all;
		final boolean cacache = argsList.remove("-ca") || all;

		try {
			if (globalconf) {
				getLogger().info("Flushing global configuration cache.");
				// Flush GlobalConfiguration
				ejb.getRAAdminSession().flushGlobalConfigurationCache();    			
			}
			if (eeprofile) {
				getLogger().info("Flushing end entity profile cache.");
				// Flush End Entity profiles
				ejb.getRAAdminSession().flushProfileCache();
			}
			if (certprofile) {
				getLogger().info("Flushing certificate profile cache.");
				// Flush Certificate profiles
				ejb.getCertStoreSession().flushProfileCache();
			}
			if (authorization) {
				getLogger().info("Flushing authorization cache.");
				// Flush access control
				ejb.getAuthorizationSession().flushAuthorizationRuleCache();
			}
			if (logconf) {
				getLogger().info("Flushing log configuration cache.");
				// Flush log configuration
				ejb.getLogSession().flushConfigurationCache();
			}
			if (cacache) {
				getLogger().info("Flushing CA cache.");
				// Flush CAs
				ejb.getCAAdminSession().flushCACache();
			}
		} catch (Exception e) {
			throw new ErrorAdminCommandException(e);
		}
	}
}
