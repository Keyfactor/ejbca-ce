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

import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionBean;

/**
 * Command for removing the catoken keystore from the specified CA.
 * 
 * @see CAAdminSessionBean#removeCAKeyStore(org.ejbca.core.model.log.Admin, String)
 * @author Markus Kilås
 * @version $Id$
 */
public class CaRemoveKeyStoreCommand extends BaseCaAdminCommand {
	
	/**
	 * Creates a new instance of CaRemoveKeyStoreCommand
	 * 
	 * @param args command line arguments
	 */
	public CaRemoveKeyStoreCommand(String[] args) {
		super(args);
	}

	/**
	 * Runs the command
	 * 
	 * @throws IllegalAdminCommandException Error in command args
	 * @throws ErrorAdminCommandException Error running command
	 */
	public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
		if (args.length < 2) {
			String msg = "Usage: CA removekeystore <CA name>";
			throw new IllegalAdminCommandException(msg);
		}
		try {
			String caName = args[1];
			getCAAdminSession().removeCAKeyStore(administrator, caName);
		} catch (Exception e) {
			throw new ErrorAdminCommandException(e);
		}
	} // execute
} // CaRemoveKeyStoreCommand
