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

import org.ejbca.core.protocol.ws.client.gen.EjbcaException_Exception;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.ui.cli.IAdminCommand;
import org.ejbca.ui.cli.IllegalAdminCommandException;


/**
 * Adds an administrator to an existing Administrator role
 *
 * @version $Id$
 */
public class GenerateCryptoTokenKeysCommand extends EJBCAWSRABaseCommand implements IAdminCommand{


    private static final int ARG_CRYPTOTOKEN_NAME    = 1;
    private static final int ARG_KEY_PAIR_ALIAS      = 2;
    private static final int ARG_KEY_SPECIFICATION   = 3;

    /**
     * Creates a new instance of Command
     *
     * @param args command line arguments
     */
    public GenerateCryptoTokenKeysCommand(String[] args) {
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
            if (args.length < 4 ) {
                getPrintStream().println("Error. Too few arguments: "+args.length);
                usage();
                System.exit(-1); // NOPMD, this is not a JEE app
            }

            String cryptotokenName = args[ARG_CRYPTOTOKEN_NAME];
            String keyAlias = args[ARG_KEY_PAIR_ALIAS];
            String keySpec = args[ARG_KEY_SPECIFICATION];
            
            getEjbcaRAWS().generateCryptoTokenKeys(cryptotokenName, keyAlias, keySpec);
            getPrintStream().println("Generate key with alias '" + keyAlias + "' in cryptotoken '" + cryptotokenName + "'");
        } catch (Exception e) {
            if (e instanceof EjbcaException_Exception) {
                EjbcaException_Exception e1 = (EjbcaException_Exception)e;
                getPrintStream().println("Error code: " + e1.getFaultInfo().getErrorCode().getInternalErrorCode());
            }
            ErrorAdminCommandException adminexp = new ErrorAdminCommandException(e);
            getPrintStream().println("Error message: " + adminexp.getLocalizedMessage());
        }
    }

    protected void usage() {
        getPrintStream().println("Command used to generate a keypair for a specific cryptotoken");
        getPrintStream().println("Usage : generatectkeys <cryptotokenName> <keypairAlias> <keySpecification>");
        getPrintStream().println();
        getPrintStream().println("Examples of key specifications: RSA2048, secp256r1, DSA1024, gost3410, dstu4145");
    }
}
