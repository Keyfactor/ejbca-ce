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

import javax.ejb.EJB;

import org.apache.commons.lang.StringUtils;
import org.ejbca.core.ejb.ra.UserAdminSessionRemote;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ra.ExtendedInformation;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.ui.cli.ErrorAdminCommandException;

/**
 * Set the Subject Directory Attributes for a user.
 *
 * @version $Id$
 */
public class RaSetSubjDirAttrCommand extends BaseRaAdminCommand {

    @EJB
    private UserAdminSessionRemote userAdminSession;
    
	public String getMainCommand() { return MAINCOMMAND; }
	public String getSubCommand() { return "setsubjectdirattr"; }
	public String getDescription() { return "Set the Subject Directory Attributes for a user"; }

    public void execute(String[] args) throws ErrorAdminCommandException {
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
            	UserDataVO uservo = userAdminSession.findUser(getAdmin(), username);
            	ExtendedInformation ext = uservo.getExtendedinformation();
            	ext.setSubjectDirectoryAttributes(attributes);
            	uservo.setExtendedinformation(ext);
            	userAdminSession.changeUser(getAdmin(), uservo, false);
            } catch (AuthorizationDeniedException e) {
            	getLogger().error("Not authorized to change userdata.");
            } catch (UserDoesntFullfillEndEntityProfile e) {
            	getLogger().error("Given userdata doesn't fullfill end entity profile. : " + e.getMessage());
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }
}
