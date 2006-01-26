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
import java.util.Iterator;

import org.ejbca.core.model.ra.UserDataVO;





/**
 * List users with specified status in the database.
 *
 * @version $Id: RaListUsersCommand.java,v 1.2 2006-01-26 14:17:57 anatom Exp $
 *
 * @see org.ejbca.core.ejb.ra.UserDataLocal
 */
public class RaListUsersCommand extends BaseRaAdminCommand {
    /**
     * Creates a new instance of RaListUsersCommand
     *
     * @param args command line arguments
     */
    public RaListUsersCommand(String[] args) {
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
                getOutputStream().println("Usage: RA listusers <status>");
                getOutputStream().println(
                    "Status: NEW=10; FAILED=11; INITIALIZED=20; INPROCESS=30; GENERATED=40; HISTORICAL=50");

                return;
            }

            int status = Integer.parseInt(args[1]);
            Collection coll = getAdminSession().findAllUsersByStatus(administrator, status);
            Iterator iter = coll.iterator();

            while (iter.hasNext()) {
                UserDataVO data = (UserDataVO) iter.next();
                getOutputStream().println("User: " + data.getUsername() + ", \"" + data.getDN() +
                    "\", \"" + data.getSubjectAltName() + "\", " + data.getEmail() + ", " +
                    data.getStatus() + ", " + data.getType() + ", " + data.getTokenType() + ", " + data.getHardTokenIssuerId());
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }

    // execute
}
