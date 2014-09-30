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

package org.ejbca.ui.cli.ra;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * Set the SubjectDN for an end entity.
 *
 * @version $Id$
 */
public class SetSubjectDNCommand extends BaseRaCommand {

    private static final Logger log = Logger.getLogger(SetSubjectDNCommand.class);

    private static final String USERNAME_KEY = "--username";
    private static final String DN_KEY = "--dn";

    {
        registerParameter(new Parameter(USERNAME_KEY, "Username", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Username of the end entity to modify."));
        registerParameter(new Parameter(DN_KEY, "Subject DN", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The new subject DN."));
    }

    @Override
    public String getMainCommand() {
        return "setsubjectdn";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {

        String username = parameters.get(USERNAME_KEY);
        String subjectDN = parameters.get(DN_KEY);
        if (StringUtils.isEmpty(subjectDN)) {
            getLogger().error("SubjectDN must be supplied.");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        getLogger().info("Setting subjectDN '" + subjectDN + "' for end entity with username " + username);
        try {
            EndEntityInformation uservo = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class).findUser(
                    getAuthenticationToken(), username);
            uservo.setDN(subjectDN);
            EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class).changeUser(getAuthenticationToken(), uservo, false);
            return CommandResult.SUCCESS;
        } catch (AuthorizationDeniedException e) {
            getLogger().error("Not authorized to change end entity.");
        } catch (UserDoesntFullfillEndEntityProfile e) {
            getLogger().error("Given end entity doesn't fullfill end entity profile. : " + e.getMessage());
        } catch (CADoesntExistsException e) {
            getLogger().error("ERROR: " + e.getMessage());
        } catch (WaitingForApprovalException e) {
            getLogger().error("ERROR: " + e.getMessage());
        } catch (EjbcaException e) {
            getLogger().error("ERROR: " + e.getMessage());
        }
        return CommandResult.FUNCTIONAL_FAILURE;
    }

    @Override
    public String getCommandDescription() {
        return "Set or update the SubjectDN for an end entity";
    }

    @Override
    public String getFullHelpText() {
        return getCommandDescription()
                + "\n\nThe SubjectDN fields are: emailAddress=<string>, UID=< unique identifier>, CN=<common name>, serialNumber=<serialnumber>, "
                + "givenName=<string>, initials=<string>, surname=<string>, title=<string>, "
                + "OU=<the organizational unit>, O=<the organization>, L=<locality>, ST=<state of province>, "
                + "DC=<domain component>, C=<two letter ISO3166>, unstructuredAddress=<IP address>, "
                + "unstructuredName=<domain name>, postalCode=<string>, businessCategory=<organization type>, "
                + "dnQualifier=<string>, postalAddress=<the postal address>, telephoneNumber=<telephone number>, "
                + "pseudonym=<string>, streetAddress=<string>, name=<string>, CIF=<tax ID code for companies in Spain>, "
                + "NIF=<tax ID number for companied in Spain>";
    }

    protected Logger getLogger() {
        return log;
    }

}
