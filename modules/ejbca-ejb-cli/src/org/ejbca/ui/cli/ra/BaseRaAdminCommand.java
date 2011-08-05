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
 
package org.ejbca.ui.cli.ra;

import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.ejbca.ui.cli.BaseCommand;

/**
 * Base for RA commands, contains common functions for RA operations
 *
 * @version $Id$
 */
public abstract class BaseRaAdminCommand extends BaseCommand {

	public static final String MAINCOMMAND = "ra";
	
	//private Admin admin = new Admin(Admin.TYPE_RA_USER, "cli");
	private AuthenticationToken admin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("cli"));
	@Override
	protected AuthenticationToken getAdmin() { return admin; }
}
