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

import org.ejbca.config.AvailableProtocolsConfiguration.AvailableProtocols;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * CLI command for retrieving enabled/disable status of EJBCA protocol(s).
 * 
 * @version $Id$
 */
public class ProtocolsStatusCommand extends BaseProtocolsConfigCommand {

    {
        registerParameter(new Parameter(KEY_NAME, "Protocol", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Name of the protocol to show status for."));
    }

    @Override
    public String getMainCommand() {
        return "status";
    }

    @Override
    public String getCommandDescription() {
        return "Get enabled/disabled status of EJBCA protocol(s).";
    }

    @Override
    protected CommandResult execute(final ParameterContainer parameters) {
        final String requestedProtocolName = parameters.get(KEY_NAME);
        final LinkedHashMap<String, Boolean> availableProtocolStatusMap = (LinkedHashMap<String, Boolean>) getAvailableProtocolsConfiguration().getAllProtocolsAndStatus();
        if (requestedProtocolName==null) {
            final int padding = getMaxStringLength(availableProtocolStatusMap.keySet());
            for (final String protocolName : availableProtocolStatusMap.keySet()) {
                showProtocolStatus(availableProtocolStatusMap, protocolName, padding);
            }
        } else {
            final AvailableProtocols availableProtocol = getAvailableProtocolFromParameter(requestedProtocolName);
            if (availableProtocol==null) {
                log.error("Unknown protocol '" + requestedProtocolName + "'");
                return CommandResult.CLI_FAILURE;
            }
            showProtocolStatus(availableProtocolStatusMap, availableProtocol.getName(), 0);
        }
        return CommandResult.SUCCESS;
    }
}
