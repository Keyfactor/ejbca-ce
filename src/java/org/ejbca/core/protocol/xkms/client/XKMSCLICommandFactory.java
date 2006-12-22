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
 
package org.ejbca.core.protocol.xkms.client;

import org.ejbca.ui.cli.IAdminCommand;

/**
 * Factory for XKMS CLI Commands.
 *
 * @version $Id: XKMSCLICommandFactory.java,v 1.1 2006-12-22 09:21:39 herrvendil Exp $
 * @author Philip Vendil
 */
public class XKMSCLICommandFactory {
    /**
     * Cannot create an instance of this class, only use static methods.
     */
    private XKMSCLICommandFactory() {
    }

    /**
     * Returns an Admin Command object based on contents in args[0].
     *
     * @param args array of arguments typically passed from main().
     *
     * @return Command object or null if args[0] does not specify a valid command.
     */
    public static IAdminCommand getCommand(String[] args) {
        if (args.length < 1) {
            return null;
        }        
        
        if (args[0].equals("locate")) {
            return new LocateCommand(args);
        }
        
        else {
            return null;
        }
    }

    // getCommand
}


