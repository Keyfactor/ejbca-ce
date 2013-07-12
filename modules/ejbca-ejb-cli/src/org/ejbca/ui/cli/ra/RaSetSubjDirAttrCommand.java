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

import org.apache.commons.lang.StringUtils;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfileException;
import org.ejbca.ui.cli.CliUsernameException;
import org.ejbca.ui.cli.ErrorAdminCommandException;

/**
 * Set the Subject Directory Attributes for a user.
 *
 * @version $Id$
 */
public class RaSetSubjDirAttrCommand extends BaseRaAdminCommand {

	public String getMainCommand() { return MAINCOMMAND; }
	public String getSubCommand() { return "setsubjectdirattr"; }
	public String getDescription() { return "Set the Subject Directory Attributes for a user"; }

    public void execute(String[] args) throws ErrorAdminCommandException {
        try {
            args = parseUsernameAndPasswordFromArgs(args);
        } catch (CliUsernameException e) {
            return;
        }
        
        try {
            if (args.length < 3) {
    			getLogger().info("Description: " + getDescription());
            	getLogger().info("Usage: " + getCommand() + " <username> \"subject directory attributes\"");
            	getLogger().info(" Attributes are: dateOfBirth=<19590927>, placeOfBirth=<string>, gender=<M/F>, countryOfCitizenship=<two letter ISO3166>, countryOfResidence=<two letter ISO3166>");
                return;
            }
            String username = args[1];
            String attributes = args[2];
            if (StringUtils.isEmpty(attributes)) {
            	getLogger().error("Subject directory attributes must be supplied.");
            	return;
            }
            getLogger().info("Setting subject directory attributes '" + attributes + "' for user " + username);
            try {
            	EndEntityInformation uservo = ejb.getRemoteSession(EndEntityAccessSessionRemote.class).findUser(getAdmin(cliUserName, cliPassword), username);
            	ExtendedInformation ext = uservo.getExtendedinformation();
            	if (ext == null) {
            		ext = new ExtendedInformation();
            	}
            	ext.setSubjectDirectoryAttributes(attributes);
            	uservo.setExtendedinformation(ext);
            	ejb.getRemoteSession(EndEntityManagementSessionRemote.class).changeUser(getAdmin(cliUserName, cliPassword), uservo, false);
            } catch (AuthorizationDeniedException e) {
            	getLogger().error("Not authorized to change userdata.");
            } catch (UserDoesntFullfillEndEntityProfileException e) {
            	getLogger().error("Given userdata doesn't fullfill end entity profile. : " + e.getMessage());
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }
}
