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
 
package se.anatom.ejbca.admin;

/**
 * Starts an external service needed for user administrations, runs in the same JVM.
 *
 * @version $Id: RaStartServiceCommand.java,v 1.6 2004-10-13 07:14:46 anatom Exp $
 */
public class RaStartServiceCommand extends BaseRaAdminCommand {
    /**
     * Creates a new instance of StartServiceCommand
     *
     * @param args command line arguments
     */
    public RaStartServiceCommand(String[] args) {
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
            getAdminSession().startExternalService(args);
            getOutputStream().println("External service started");
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }

    // execute
}
