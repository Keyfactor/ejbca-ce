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
 
package org.ejbca.ui.cli.ra;

import org.ejbca.ui.cli.infrastructure.command.EjbcaCliUserCommandBase;

/**
 * Base for RA commands, contains common functions for RA operations
 *
 * @version $Id$
 */
public abstract class BaseRaCommand extends EjbcaCliUserCommandBase {

	public static final String MAINCOMMAND = "ra";
	
    @Override
    public String[] getCommandPath() {
        return new String[] { MAINCOMMAND };
    }

}
