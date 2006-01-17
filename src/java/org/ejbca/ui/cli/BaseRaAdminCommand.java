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

import org.ejbca.core.model.log.Admin;



/**
 * Base for RA commands, contains comom functions for RA operations
 *
 * @version $Id: BaseRaAdminCommand.java,v 1.1 2006-01-17 20:28:05 anatom Exp $
 */
public abstract class BaseRaAdminCommand extends BaseAdminCommand {

    /**
     * Creates a new instance of BaseRaAdminCommand
     *
     * @param args command line arguments
     */
    public BaseRaAdminCommand(String[] args) {
        super(args, Admin.TYPE_RACOMMANDLINE_USER);
    }    
    
}
