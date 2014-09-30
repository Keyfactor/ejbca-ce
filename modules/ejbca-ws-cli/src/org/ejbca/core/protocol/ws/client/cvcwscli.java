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

import org.ejbca.ui.cli.IAdminCommand;

/**
 * Implements the EJBCA WS command line interface specific for CVC requests
 *
 * @version $Id$
 */
public class cvcwscli  {

	public static void main(String[] args) {
        try {
            IAdminCommand cmd = EJBCAWSRACommandFactory.getCommand(args);

            if (cmd != null) {
                cmd.execute();
            } else {
                System.out.println(
                    "Usage: cvcrequest cvcgetchain cvcprint cvcpem");
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
            e.printStackTrace();
            System.exit(-1); // NOPMD, this is not a JEE app
        }
    }
}
