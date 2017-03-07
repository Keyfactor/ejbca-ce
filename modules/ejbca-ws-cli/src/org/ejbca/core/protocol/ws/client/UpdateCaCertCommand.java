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

import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.core.protocol.ws.client.gen.EjbcaException_Exception;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.ui.cli.IAdminCommand;
import org.ejbca.ui.cli.IllegalAdminCommandException;

/**
 * Updates an external X.509 CA or CVC CA with the given name.
 *
 * @version $Id: UpdateCaCertCommand.java 22553 2017-02-17 13:00:00Z anjakobs $
 */
public class UpdateCaCertCommand extends EJBCAWSRABaseCommand implements IAdminCommand {

    private static final int ARG_CANAME = 1;
    private static final int ARG_CACHAIN = 2;

    /**
     * Creates a new instance of Command
     *
     * @param args command line arguments
     */
    public UpdateCaCertCommand(String[] args) {
        super(args);
    }

    /**
     * Runs the command
     *
     * @throws IllegalAdminCommandException Error in command args
     * @throws ErrorAdminCommandException Error running command
     */
    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
        try {
            if (args.length < 3 || args.length > 3) {
                getPrintStream().println("Number of arguments: " + args.length);
                usage();
                System.exit(-1); // NOPMD, this is not a JEE app
            }

            CryptoProviderTools.installBCProvider();

            final String caname = args[ARG_CANAME];
            final String file = args[ARG_CACHAIN];
            getPrintStream().println("Update external CA: " + caname);
            getPrintStream().println("Update external CA chain file: " + file);

            final byte[] cachain = CertTools.readCertificateChainAsArrayOrThrow(file);
            getEjbcaRAWS().updateCaCert(caname, cachain);

            getPrintStream().println("CA updated sucessfully.");
        } catch (Exception e) {
            if (e instanceof EjbcaException_Exception) {
                EjbcaException_Exception e1 = (EjbcaException_Exception) e;
                getPrintStream().println("Error code is: " + e1.getFaultInfo().getErrorCode().getInternalErrorCode());
            }
            throw new ErrorAdminCommandException(e);
        }
    }

    protected void usage() {
        getPrintStream().println("Command used to update an external CA certificate. Can be an X.509 or CVC CA.");
        getPrintStream().println("Usage : updatecacert <caname> <cachainfile>\n\n");
        getPrintStream().println("Caname is the name of an existing CA in EJBCA.");
        getPrintStream().println(
                "Cachainfile is a file with the certificate chain of the external CA. This can be a file with several PEM certificates in it, or a file with a single PEM or binary Root CA certificate.");
    }
}
