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

import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.certificate.CertificateDataSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * Get the quantity of total issued or active certificates
 */
public class GetCertificateCountCommand extends BaseRaCommand {

    private static final Logger log = Logger.getLogger(GetCertificateCountCommand.class);

    private static final String ACTIVE_ONLY = "--activeOnly";
    {
        registerParameter(new Parameter(ACTIVE_ONLY, "Active only", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "Count only active certificates, or all. Default value (if parameter not provided) is false."));
    }

    @Override
    protected CommandResult execute(ParameterContainer parameterContainer) {

        final String isActiveParam = parameterContainer.get(ACTIVE_ONLY);
        final boolean isActive = !StringUtils.isEmpty(isActiveParam) && Boolean.parseBoolean(isActiveParam);
        try {
            final Long result = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateDataSessionRemote.class).getCertificateCount(
                    getAuthenticationToken(), isActive);
            getLogger().info("Total " + (isActive ? " active " : "") + "certificate count is:  " + result + ".");
            return CommandResult.SUCCESS;
        } catch (AuthorizationDeniedException e) {
            log.error("ERROR: CLI use not authorized to perform certificate count " );
        }
        return CommandResult.FUNCTIONAL_FAILURE;
    }

    @Override
    public String getFullHelpText() {
        StringBuilder sb = new StringBuilder();
        sb.append(getCommandDescription()).append("\n");
        sb.append("Add --activeOnly=true to get only active certificate count" );
        return sb.toString();
    }

    @Override
    protected Logger getLogger() {
        return log;
    }

    @Override
    public String getMainCommand() {
        return "getcertificatecount";
    }

    @Override
    public String getCommandDescription() {
        return "Get the quantity of total issued or active certificates";
    }
}
