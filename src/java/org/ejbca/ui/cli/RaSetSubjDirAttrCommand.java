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

import org.apache.commons.lang.StringUtils;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ra.ExtendedInformation;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;



/**
 * Set the clear text password for a user in the database.  Clear text passwords are used for batch
 * generation of keystores (pkcs12/pem).
 *
 * @version $Id: RaSetSubjDirAttrCommand.java,v 1.1 2006-06-03 18:10:46 anatom Exp $
 */
public class RaSetSubjDirAttrCommand extends BaseRaAdminCommand {
    /**
     * Creates a new instance of RaSetClearPwdCommand
     *
     * @param args command line arguments
     */
    public RaSetSubjDirAttrCommand(String[] args) {
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
            if (args.length < 3) {
                getOutputStream().println("Usage: RA setsubjectdirattr <username> \"subject directory attributes\"");
                getOutputStream().println("Attributes are: dateOfBirth=<19590927>, placeOfBirth=<string>, gender=<M/F>, countryOfCitizenship=<two letter ISO3166>, countryOfResidence=<two letter ISO3166>");
                return;
            }

            String username = args[1];
            String attributes = args[2];
            if (StringUtils.isEmpty(attributes)) {
            	getOutputStream().println("Subject directory attributes must be supplied.");
            	return;
            }
            getOutputStream().println("Setting subject directory attributes '" + attributes + "' for user " + username);

            try {
            	UserDataVO uservo = getAdminSession().findUser(administrator, username);
            	ExtendedInformation ext = uservo.getExtendedinformation();
            	ext.setSubjectDirectoryAttributes(attributes);
            	uservo.setExtendedinformation(ext);
            	getAdminSession().changeUser(administrator, uservo, false);
            } catch (AuthorizationDeniedException e) {
                getOutputStream().println("Error : Not authorized to change userdata.");
            } catch (UserDoesntFullfillEndEntityProfile e) {
                getOutputStream().println("Error : Given userdata doesn't fullfill end entity profile. : " + e.getMessage());
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }

    // execute
}
