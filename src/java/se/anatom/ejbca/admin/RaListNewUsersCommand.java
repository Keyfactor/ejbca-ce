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

import java.util.Collection;
import java.util.Iterator;

import se.anatom.ejbca.ra.UserAdminData;
import se.anatom.ejbca.ra.UserDataLocal;


/**
 * List users with status NEW in the database.
 *
 * @version $Id: RaListNewUsersCommand.java,v 1.9 2004-04-16 07:38:57 anatom Exp $
 *
 * @see se.anatom.ejbca.ra.UserDataLocal
 */
public class RaListNewUsersCommand extends BaseRaAdminCommand {
    /**
     * Creates a new instance of RaListNewUsersCommand
     *
     * @param args command line arguments
     */
    public RaListNewUsersCommand(String[] args) {
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
            Collection coll = getAdminSession().findAllUsersByStatus(administrator,
                    UserDataLocal.STATUS_NEW);
            Iterator iter = coll.iterator();

            while (iter.hasNext()) {
                UserAdminData data = (UserAdminData) iter.next();
                System.out.println("New User: " + data.getUsername() + ", \"" + data.getDN() +
                    "\", \"" + data.getSubjectAltName() + "\", " + data.getEmail() + ", " +
                    data.getStatus() + ", " + data.getType() + ", " + data.getTokenType());
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }

    // execute
}
