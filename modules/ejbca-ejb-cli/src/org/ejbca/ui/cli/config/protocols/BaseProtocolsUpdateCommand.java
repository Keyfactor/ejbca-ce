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
package org.ejbca.ui.cli.config.protocols;

import java.util.LinkedHashMap;

import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.config.AvailableProtocolsConfiguration;
import org.ejbca.config.AvailableProtocolsConfiguration.AvailableProtocols;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * Base CLI command to enable or disable an EJBCA protocol.
 * 
 * @version $Id$
 */
public abstract class BaseProtocolsUpdateCommand extends BaseProtocolsConfigCommand {

    {
        registerParameter(new Parameter(KEY_NAME, "Protocol", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Name of the protocol."));
    }
    
    protected abstract boolean getNewStatus();

    /** Common method for updating the status of a protocol */
    protected CommandResult execute(final ParameterContainer parameters) {
        final String requestedProtocolName = parameters.get(KEY_NAME);
        final AvailableProtocols availableProtocol = getAvailableProtocolFromParameter(requestedProtocolName);
        if (availableProtocol==null) {
            log.error("Unknown protocol '" + requestedProtocolName + "'");
            return CommandResult.CLI_FAILURE;
        }
        try {
            final AvailableProtocolsConfiguration availableProtocolsConfiguration = getAvailableProtocolsConfiguration();
            availableProtocolsConfiguration.setProtocolStatus(availableProtocol.getName(), getNewStatus());
            getGlobalConfigurationSession().saveConfiguration(getAuthenticationToken(), availableProtocolsConfiguration);
        } catch (AuthorizationDeniedException e) {
            return CommandResult.AUTHORIZATION_FAILURE;
        } finally {
            final LinkedHashMap<String, Boolean> availableProtocolStatusMap = (LinkedHashMap<String, Boolean>) getAvailableProtocolsConfiguration().getAllProtocolsAndStatus();
            showProtocolStatus(availableProtocolStatusMap, availableProtocol.getName(), 0);
        }
        return CommandResult.SUCCESS;
    }
}
