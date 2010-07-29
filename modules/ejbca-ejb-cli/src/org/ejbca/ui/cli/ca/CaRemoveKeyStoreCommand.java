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

package org.ejbca.ui.cli.ca;

import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.ui.cli.ErrorAdminCommandException;

/**
 * Remove the CA token keystore from a CA.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public class CaRemoveKeyStoreCommand extends BaseCaAdminCommand {

    private CAAdminSessionRemote caAdminSession = ejb.getCAAdminSession();
    
	public String getMainCommand() { return MAINCOMMAND; }
	public String getSubCommand() { return "removekeystore"; }
	public String getDescription() { return "Remove the CA token keystore from a CA"; }

    public void execute(String[] args) throws ErrorAdminCommandException {
		if (args.length < 2) {
    		getLogger().info("Description: " + getDescription());
    		getLogger().info("Usage: " + getCommand() + " <CA name>");
			return;
		}
		try {
			String caName = args[1];
			caAdminSession.removeCAKeyStore(getAdmin(), caName);
		} catch (Exception e) {
			throw new ErrorAdminCommandException(e);
		}
	}
}
