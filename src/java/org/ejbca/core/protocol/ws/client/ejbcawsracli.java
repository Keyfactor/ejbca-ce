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
 
package org.ejbca.core.protocol.ws.client;

import org.ejbca.ui.cli.IAdminCommand;

/**
 * Implements the EJBCA RA WS command line interface
 *
 * @version $Id: ejbcawsracli.java,v 1.1 2006-09-17 23:00:25 herrvendil Exp $
 */
public class ejbcawsracli  {
    /**
     * main Client
     *
     * @param args command line arguments
     */
    public static void main(String[] args) {
        try {
            IAdminCommand cmd = EJBCAWSRACommandFactory.getCommand(args);

            if (cmd != null) {
                cmd.execute();
            } else {
                System.out.println(
                    "Usage: edituser | finduser | findcerts | pkcs10req | pkcs12req | revokecert | revoketoken | revokeuser | checkrevokationstatus");
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
            e.printStackTrace();
            System.exit(-1);
        }
    }
}
