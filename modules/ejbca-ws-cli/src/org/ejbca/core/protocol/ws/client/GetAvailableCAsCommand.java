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

package org.ejbca.core.protocol.ws.client;

import java.util.List;

import org.ejbca.core.protocol.ws.client.gen.AuthorizationDeniedException_Exception;
import org.ejbca.core.protocol.ws.client.gen.NameAndId;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.ui.cli.IAdminCommand;
import org.ejbca.ui.cli.IllegalAdminCommandException;

/**
 * Lists CAs the administrator have access to read
 */
public class GetAvailableCAsCommand extends EJBCAWSRABaseCommand implements IAdminCommand {

	/**
	 * Creates a new instance
	 *
	 * @param args command line arguments
	 */
	public GetAvailableCAsCommand(String[] args) {
		super(args);
	}

	@Override
	public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
		try {
			try{
				final List<NameAndId> result =  getEjbcaRAWS().getAvailableCAs();
				for (NameAndId entry : result) {
	                getPrintStream().println(entry.getName() + " : " + entry.getId());				    
				}
			} catch (AuthorizationDeniedException_Exception e) {
				getPrintStream().println("Error : " + e.getMessage());
			}
		} catch (Exception e) {
			throw new ErrorAdminCommandException(e);
		}
	}

	@Override
	protected void usage() {
		getPrintStream().println("Command used to list CAs that the administrator has access to.");
		getPrintStream().println("Usage : getavailablecas");
	}
}
