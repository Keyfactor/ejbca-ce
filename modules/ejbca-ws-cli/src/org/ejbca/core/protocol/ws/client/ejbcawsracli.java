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
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.ui.cli.IAdminCommand;
import org.ejbca.ui.cli.IllegalAdminCommandException;

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
                    "Usage: edituser | finduser | findcerts | pkcs10req | pkcs12req | certreq | revokecert | " +
                    "getpublisherqueuelength | revoketoken | revokeuser | checkrevocationstatus | generatenewuser | " +
                    "createcrl | cacertrequest | cacertresponse | customlog | getprofile | createcryptotoken | " + 
                    "generatectkeys | createca | addadmintorole | removeadminfromrole | getexpiredcerts | " +
                    "getexpiredcertsbyissuer | getexpiredcertsbytype | stress");
            }
        } catch (ErrorAdminCommandException e) {
            final Throwable cause = e.getCause();
            if ( Thread.currentThread().getStackTrace().length > 12 && cause instanceof SecurityException ) {
                throw (SecurityException)cause; // throw it if called by clientToolBoxTest and exit exception. clientToolBox call has a length of 8. 12 gives some margin for code changes.
            }
            if (cause instanceof EjbcaException_Exception) {
                final EjbcaException_Exception ejbcaex = (EjbcaException_Exception)cause;
                final EjbcaException ee = ejbcaex.getFaultInfo();
                System.out.println("Error: "+ee.getErrorCode().getInternalErrorCode()+": "+ee.getMessage());
            } else {
                System.out.println(e.getMessage());
            }
            e.printStackTrace(System.err);
            System.exit(-1); // NOPMD, this is not a JEE app
        } catch (IllegalAdminCommandException e) {
            System.out.println(e.getMessage());
            System.exit(-2); // NOPMD, this is not a JEE app
        }
    }
}
