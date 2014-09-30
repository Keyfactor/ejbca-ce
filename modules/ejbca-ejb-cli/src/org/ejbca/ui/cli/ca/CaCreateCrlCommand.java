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
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * Issues a new CRL from the CA.
 *
 * @version $Id$
 */
public class CaCreateCrlCommand extends BaseCaAdminCommand {

    private static final Logger log = Logger.getLogger(CaCreateCrlCommand.class);

    private static final String CA_NAME_KEY = "--caname";
    private static final String DELTA_KEY = "-delta";

    {
        registerParameter(new Parameter(CA_NAME_KEY, "CA Name", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "If no caname is given, CRLs will be created for all the CAs where it is neccessary."));
        registerParameter(new Parameter(DELTA_KEY, "", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.FLAG,
                "Set if a Delta CRL is desired"));
    }

    @Override
    public String getMainCommand() {
        return "createcrl";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {
        String caName = parameters.get(CA_NAME_KEY);
        boolean deltaCrl = parameters.get(DELTA_KEY) != null;
        if (caName == null) {
            createCRL((String) null, deltaCrl);
        } else {
            CryptoProviderTools.installBCProvider();
            // createCRL prints info about crl generation
            try {
                String issuerDn = getIssuerDN(getAuthenticationToken(), caName);
                createCRL(issuerDn, deltaCrl);
            } catch (CADoesntExistsException e) {
                log.error("No CA named " + caName + " exists.");
                return CommandResult.FUNCTIONAL_FAILURE;
            } catch (AuthorizationDeniedException e) {
                log.error("CLI user is not authorized to CA " + caName);
                return CommandResult.AUTHORIZATION_FAILURE;
            }      
        }
        return CommandResult.SUCCESS;
    }

    @Override
    public String getCommandDescription() {
        return "Issues a new CRL from the CA.";
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
