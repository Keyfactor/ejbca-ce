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
 
package org.ejbca.core.protocol.xkms.client;

import org.ejbca.ui.cli.IAdminCommand;

/**
 * Implements the EJBCA RA WS command line interface
 *
 * @version $Id$
 */
public class xkmscli  {
    /**
     * main Client
     *
     * @param args command line arguments
     */
    public static void main(String[] args) {
        try {
            IAdminCommand cmd = XKMSCLICommandFactory.getCommand(args);

            if (cmd != null) {
                cmd.execute();
            } else {
                System.out.println(
                    "Usage: locate | register | reissue | recover | revoke\n\n" +
                    "Please note that XKMS cannot be used with end entites created with the EMPTY end entity profile for security reasons.");

            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
            e.printStackTrace();
            System.exit(-1); // NOPMD, this is not a JEE app
        }
    }
}
