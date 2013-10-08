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

import org.ejbca.ui.cli.BaseCommand;

/**
 * Base for RA commands, contains common functions for RA operations
 *
 * @version $Id$
 */
public abstract class BaseRaAdminCommand extends BaseCommand {

	public static final String MAINCOMMAND = "ra";
	
    public String getMainCommand() {
        return MAINCOMMAND;
    }
    
    @Override
    public String[] getMainCommandAliases() {
        return new String[]{};
    }
}
