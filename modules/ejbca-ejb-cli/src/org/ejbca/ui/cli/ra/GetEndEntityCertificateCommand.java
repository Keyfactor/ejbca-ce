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

import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import org.apache.log4j.Logger;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * Output all certificates for an end entity.
 *
 * @version $Id$
 */
public class GetEndEntityCertificateCommand extends BaseRaCommand {
    
    private static final Logger log = Logger.getLogger(GetEndEntityCertificateCommand.class);
    
    private static final String COMMAND = "getendentitycert";
    private static final String OLD_COMMAND = "getusercert";
    
    private static final Set<String> ALIASES = new HashSet<String>();
    static {
        ALIASES.add(OLD_COMMAND);
    }
    
    private static final String USERNAME_KEY = "--username";

    {
        registerParameter(new Parameter(USERNAME_KEY, "Username", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Username for the end entity whose certificate to get."));
    }
    
    @Override
    public Set<String> getMainCommandAliases() {
        return ALIASES;
    }

    @Override
    public String getMainCommand() {
        return COMMAND;
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {
            final String username = parameters.get(USERNAME_KEY);
            final Collection<CertificateDataWrapper> wrappers = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class).getCertificateDataByUsername(username);
            if (wrappers != null) {
                final Collection<Certificate> certs = new ArrayList<Certificate>();
                for (CertificateDataWrapper wrapper : wrappers) {
                    certs.add(wrapper.getCertificate());
                }
            	try {
                    getLogger().info(new String(CertTools.getPemFromCertificateChain(certs)));
                    return CommandResult.SUCCESS;
                } catch (CertificateEncodingException e) {
                   throw new IllegalStateException("Newly retrieved certificate could not be parsed", e);
                }
            } else {
            	getLogger().info("End Entity with username '" + username + "' does not exist.");
            	 return CommandResult.FUNCTIONAL_FAILURE;
            }

    }
    
    @Override
    public String getCommandDescription() {
        return "Output all certificates for an end entity";
    }

    @Override
    public String getFullHelpText() {
        return getCommandDescription();
    }

    protected Logger getLogger() {
        return log;
    }
}
