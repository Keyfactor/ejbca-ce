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

import java.util.Collection;

import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.util.CertTools;





/**
 * Output all certificates to stdout for a specific user.
 *
 * @version $Id$
 */
public class RaGetUserCertCommand extends BaseRaAdminCommand {
    /**
     * Creates a new instance of RaFindUserCommand
     *
     * @param args command line arguments
     */
    public RaGetUserCertCommand(String[] args) {
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
            if (args.length < 2) {
                getOutputStream().println("Usage: ra getusercert <username>");

                return;
            }

            final String username = args[1];
            
            try {
                final Collection data = getCertificateStoreSession().findCertificatesByUsername(administrator, username);
                if (data != null) {
                    getOutputStream().println(new String(CertTools.getPEMFromCerts(data)));
                } else {
                    getOutputStream().println("User '" + username + "' does not exist.");
                }
            } catch (AuthorizationDeniedException e) {
                getOutputStream().println("Error : Not authorized to view user.");
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }

    // execute
}
