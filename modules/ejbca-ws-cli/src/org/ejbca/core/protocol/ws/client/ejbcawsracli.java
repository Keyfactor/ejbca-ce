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

import org.ejbca.core.protocol.ws.client.gen.EjbcaException;
import org.ejbca.core.protocol.ws.client.gen.EjbcaException_Exception;
import org.ejbca.ui.cli.IAdminCommand;

/**
 * Implements the EJBCA RA WS command line interface
 *
 * @version $Id$
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
                    "Usage: edituser | finduser | findcerts | pkcs10req | pkcs12req | certreq | revokecert | getpublisherqueuelength | revoketoken | revokeuser | checkrevocationstatus | generatenewuser | createcrl | cacertrequest | cacertresponse | customlog | stress");
            }
        } catch (Exception e) {
        	Throwable cause = e.getCause();
        	if (cause instanceof EjbcaException_Exception) {
        		EjbcaException_Exception ejbcaex = (EjbcaException_Exception)cause;
        		EjbcaException ee = ejbcaex.getFaultInfo();
        		System.out.println("Error: "+ee.getErrorCode().getInternalErrorCode()+": "+ee.getMessage());
			} else {
	            System.out.println(e.getMessage());
			}
            e.printStackTrace();				
            System.exit(-1); // NOPMD, this is not a JEE app
        }
    }
}
