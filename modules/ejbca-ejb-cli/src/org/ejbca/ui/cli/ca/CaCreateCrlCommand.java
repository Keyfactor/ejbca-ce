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

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

import org.apache.log4j.Logger;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

import com.keyfactor.util.CryptoProviderTools;

/**
 * Issues a new CRL from the CA.
 *
 */
public class CaCreateCrlCommand extends BaseCaAdminCommand {

    private static final Logger log = Logger.getLogger(CaCreateCrlCommand.class);

    private static final String CA_NAME_KEY = "--caname";
    private static final String DELTA_KEY = "-delta";
    private static final String UPDATE_DATE = "--updateDate";

    {
        registerParameter(new Parameter(CA_NAME_KEY, "CA Name", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "If no caname is given, CRLs will be created for all the CAs where it is neccessary."));
        registerParameter(new Parameter(DELTA_KEY, "", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.FLAG,
                "Set if a Delta CRL is desired"));
        registerParameter(new Parameter(UPDATE_DATE, "yyyyMMddHHmmss", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "Set a custom update date (start date) for issuing CRLs for the future. Do not use with Delta CRLs."));
    }

    @Override
    public String getMainCommand() {
        return "createcrl";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {
        String caName = parameters.get(CA_NAME_KEY);
        boolean deltaCrl = parameters.get(DELTA_KEY) != null;
        final String updateDate = parameters.get(UPDATE_DATE);
        Date udate = null;
        if (updateDate != null) {
            SimpleDateFormat format = new SimpleDateFormat("yyyyMMddHHmmss");
            try {
                udate = format.parse(updateDate);
            } catch (ParseException e) {
                log.error("Date format of '" + updateDate + "' was not valid.");
                return CommandResult.CLI_FAILURE;
            }

        }
        //Delta CRLs and future updates don't mix. 
        if(deltaCrl && udate != null) {
            log.error("Do not use delta CRLs with custom validFrom times.");
            return CommandResult.CLI_FAILURE;
        }
        
        if (caName == null) {
            createCRL(null, deltaCrl, udate);
        } else {
            CryptoProviderTools.installBCProvider();
            // createCRL prints info about crl generation
            try {
                final CAInfo caInfo = getCAInfo(getAuthenticationToken(), caName);
                if(caInfo == null) {
                    throw new CADoesntExistsException();
                }
                createCRL(caInfo.getSubjectDN(), deltaCrl, udate);
            } catch (CADoesntExistsException e) {
                log.error("No CA named " + caName + " exists.");
                return CommandResult.FUNCTIONAL_FAILURE;
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
