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

import java.io.PrintStream;

/**
 * Base for all AdminCommands, contains functions for getting initial context and logging
 *
 * @version $Id: BaseAdminCommand.java,v 1.1 2006-01-17 20:28:05 anatom Exp $
 */
public abstract class BaseAdminCommand extends BaseCommand implements IAdminCommand {
    /**
     * Creates a new instance of BaseAdminCommand
     *
     * @param args command line arguments
     * @param adminType type of admin Admin.TYPE_RACOMMANDLINE_USER, or Admin.TYPE_CACOMMANDLINE_USER
     * @param outStream stream where commands write its output
     */
    public BaseAdminCommand(String[] args, int adminType, PrintStream outStream) {
        init(args, adminType, outStream);
    }

    /**
     * Creates a new instance of BaseAdminCommand
     *
     * @param args command line arguments
     * @param adminType type of admin Admin.TYPE_RACOMMANDLINE_USER, or Admin.TYPE_CACOMMANDLINE_USER
     */
    public BaseAdminCommand(String[] args, int adminType) {
        init(args, adminType, null);
    }

} //BaseAdminCommand
