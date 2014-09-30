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
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.catoken.CAToken;
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
 * Changes the signature algorithm and possible keyspec of a CA token.
 *
 * @version $Id$
 */
public class CaChangeCATokenSignAlgCommand extends BaseCaAdminCommand {

    private static final String CA_NAME_KEY = "--caname";
    private static final String SIGALG_KEY = "--sigalg";

    private static final Logger log = Logger.getLogger(CaChangeCATokenSignAlgCommand.class);

    {
        parameterHandler.registerParameter(new Parameter(CA_NAME_KEY, "CA Name", MandatoryMode.MANDATORY, StandaloneMode.ALLOW,
                ParameterMode.ARGUMENT, "The name of the CA."));
        parameterHandler.registerParameter(new Parameter(SIGALG_KEY, "Signature algorithm", MandatoryMode.MANDATORY, StandaloneMode.ALLOW,
                ParameterMode.ARGUMENT, "The signature algorithm to change to."));
    }

    @Override
    public String getMainCommand() {
        return "changecatokensignalg";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {
        log.trace(">execute()");

        CryptoProviderTools.installBCProvider(); // need this for CVC certificate
        String caName = parameters.get(CA_NAME_KEY);
        try {
            CAInfo cainfo = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(getAuthenticationToken(), caName);
            String signAlg = parameters.get(SIGALG_KEY);
            log.info("Setting new signature algorithm: " + signAlg);
            final CAToken caToken = cainfo.getCAToken();
            caToken.setSignatureAlgorithm(signAlg);
            cainfo.setCAToken(caToken);
            EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class).editCA(getAuthenticationToken(), cainfo);
            log.info("CA token signature algorithm for CA changed.");
            log.trace("<execute()");          
        } catch (AuthorizationDeniedException e) {
            log.error("CLI User was not authorized to modify CA " + caName);
            log.trace("<execute()");
            return CommandResult.AUTHORIZATION_FAILURE;
        } catch (CADoesntExistsException e) {
            log.error("No such CA with by name " + caName);
            log.error(getCaList());
            return CommandResult.FUNCTIONAL_FAILURE;
        } 
        log.trace("<execute()");
        return CommandResult.SUCCESS;
     
        
    }

    @Override
    public String getCommandDescription() {
        return "Changes the signature algorithm and possible keyspec of a CA token";
    }

    @Override
    public String getFullHelpText() {
        return "Changes the signature algorithm and possible keyspec of a CA token."
                + "\n\n"
                + "Signature alg is one of SHA1WithRSA, SHA256WithRSA, SHA256WithRSAAndMGF1, SHA224WithECDSA, SHA256WithECDSA, or any other string available in the admin-GUI."
                + "\n\n" + getCaList();
    }

    @Override
    protected Logger getLogger() {
        return log;
    }

}
