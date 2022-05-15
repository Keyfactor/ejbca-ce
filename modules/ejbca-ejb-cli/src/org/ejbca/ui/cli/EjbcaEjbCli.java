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

package org.ejbca.ui.cli;

import java.util.ServiceConfigurationError;

import javax.ejb.NoSuchEJBException;

import org.apache.log4j.Logger;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.library.CommandLibrary;

/**
 * Main entry point for the EJBCA EJB CLI
 * 
 * @version $Id$
 */
public class EjbcaEjbCli {

    private static final Logger log = Logger.getLogger(EjbcaEjbCli.class);

    public static void main(String[] args) {

        try {
            if (args.length == 0 || !CommandLibrary.INSTANCE.doesCommandExist(args)) {
                CommandLibrary.INSTANCE.listRootCommands();
            } else {
                CryptoProviderTools.installBCProvider();

                CommandResult result = CommandLibrary.INSTANCE.findAndExecuteCommandFromParameters(args);
                if (result != CommandResult.SUCCESS) {
                    System.exit(result.getReturnCode());
                }

            }
        } catch (ServiceConfigurationError e) {
            if (e.getCause() instanceof NoSuchEJBException
                    || (e.getCause() instanceof IllegalStateException && e.getCause().getLocalizedMessage().contains("No EJB receiver"))) {

                log.error("Error: CLI could not contact EJBCA instance. Either your application server is not up and running,"
                        + " EJBCA has not been deployed successfully, or some firewall rule is blocking the CLI from the application server." + "\n\n"
                        + "Please be aware that most commands will not work without the application server available.\n");

            } else {
                throw e;
            }

        }
    }
}
