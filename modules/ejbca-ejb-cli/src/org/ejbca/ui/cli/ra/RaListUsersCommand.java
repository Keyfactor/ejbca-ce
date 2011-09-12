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
 
package org.ejbca.ui.cli.ra;

import java.util.Collection;
import java.util.Iterator;

import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.ejbca.ui.cli.ErrorAdminCommandException;

/**
 * List users with specified status in the database.
 *
 * @version $Id$
 *
 * @see org.ejbca.core.ejb.ra.UserDataLocal
 */
public class RaListUsersCommand extends BaseRaAdminCommand {

	public String getMainCommand() { return MAINCOMMAND; }
	public String getSubCommand() { return "listusers"; }
	public String getDescription() { return "List users with a specified status"; }

    public void execute(String[] args) throws ErrorAdminCommandException {
        String cliUserName = "username";
        String cliPassword = "passwordhash";
        AuthenticationSubject subject = getAuthenticationSubject(cliUserName, cliPassword);
        
        try {
            if (args.length < 2) {
    			getLogger().info("Description: " + getDescription());
                getLogger().info("Usage: " + getCommand() + " <status>");
                getLogger().info(" Status: ANY=00; NEW=10; FAILED=11; INITIALIZED=20; INPROCESS=30; GENERATED=40; HISTORICAL=50");
                return;
            }
            int status = Integer.parseInt(args[1]);
            Collection<EndEntityInformation> coll = null;
            if (status==0) {
                coll = ejb.getUserAdminSession().findAllUsersByStatus(getAdmin(subject), 10);
                coll.addAll(ejb.getUserAdminSession().findAllUsersByStatus(getAdmin(subject), 11));
                coll.addAll(ejb.getUserAdminSession().findAllUsersByStatus(getAdmin(subject), 20));
                coll.addAll(ejb.getUserAdminSession().findAllUsersByStatus(getAdmin(subject), 30));
                coll.addAll(ejb.getUserAdminSession().findAllUsersByStatus(getAdmin(subject), 40));
                coll.addAll(ejb.getUserAdminSession().findAllUsersByStatus(getAdmin(subject), 50));
            } else {
                coll = ejb.getUserAdminSession().findAllUsersByStatus(getAdmin(subject), status);
            }
            Iterator<EndEntityInformation> iter = coll.iterator();
            while (iter.hasNext()) {
                EndEntityInformation data = iter.next();
                getLogger().info("User: " + data.getUsername() + ", \"" + data.getDN() +
                    "\", \"" + data.getSubjectAltName() + "\", " + data.getEmail() + ", " +
                    data.getStatus() + ", " + data.getType() + ", " + data.getTokenType() + ", " + data.getHardTokenIssuerId());
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }
}
