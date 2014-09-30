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

package org.ejbca.ui.cli.ca;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * Makes the specified HSM CA offline.
 *
 * @version $Id$
 */
public class CaDeactivateCACommand extends BaseCaAdminCommand {

    private static final Logger log = Logger.getLogger(CaDeactivateCACommand.class);

    private static final String CA_NAME_KEY = "--caname";

    {
        registerParameter(new Parameter(CA_NAME_KEY, "Name of the CA", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "If no caname is given, CRLs will be created for all the CAs where it is neccessary."));
    }

    @Override
    public String getMainCommand() {
        return "deactivateca";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {

        String caname = parameters.get(CA_NAME_KEY);
        try {
            CryptoProviderTools.installBCProvider();
            // Get the CAs info and id
            CAInfo cainfo;
            try {
                cainfo = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(getAuthenticationToken(), caname);
            } catch (CADoesntExistsException e) {
                log.error("CA " + caname + " cannot be found");
                return CommandResult.FUNCTIONAL_FAILURE;
            }
            final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
                    .getRemoteSession(CryptoTokenManagementSessionRemote.class);
            final int cryptoTokenId = cainfo.getCAToken().getCryptoTokenId();
            final boolean tokenOnline = cryptoTokenManagementSession.isCryptoTokenStatusActive(getAuthenticationToken(), cryptoTokenId);
            if (cainfo.getStatus() == CAConstants.CA_ACTIVE || tokenOnline) {
                if (cainfo.getStatus() == CAConstants.CA_ACTIVE) {
                    try {
                        EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class).deactivateCAService(getAuthenticationToken(),
                                cainfo.getCAId());
                    } catch (CADoesntExistsException e) {
                        throw new IllegalStateException("CA was not found though just retrieved.");
                    }
                    log.info("CA Service deactivated.");
                }
                if (tokenOnline) {
                    cryptoTokenManagementSession.deactivate(getAuthenticationToken(), cryptoTokenId);
                    log.info("CA CryptoToken deactivated.");
                }
            } else {
                log.error("CA Service or CryptoToken must be active for this command to do anything.");
                return CommandResult.FUNCTIONAL_FAILURE;
            }
        } catch (AuthorizationDeniedException e) {
            log.error("CLI User was not authorized to CA " + caname);
            return CommandResult.AUTHORIZATION_FAILURE;
        }
        return CommandResult.SUCCESS;

    }

    @Override
    public String getCommandDescription() {
        return "Makes the specified HSM CA offline.";
    }

    @Override
    public String getFullHelpText() {
        return getCommandDescription();
    }
    
    @Override
    protected Logger getLogger() {
        return log;
    }
}
